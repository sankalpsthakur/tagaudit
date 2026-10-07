"""Offline checks for industrial tag data. Standard library only; no network or actuation.

This file also runs on its own (`python audit.py --profile ... --csv ... --output ...`)
for air-gapped machines. OPC UA timestamps and quality codes are interpreted under
an explicit profile.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import math
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from decimal import Decimal, ROUND_FLOOR
from pathlib import Path

SCHEMA = "tagaudit.profile.v1"
LEGACY_SCHEMAS = frozenset({"forge.telemetry.audit.v1"})
REPORT_SCHEMA = "tagaudit.report.v1"
QUALITY_ENCODINGS = ("opcua_status_code", "opc_da_quality", "quality_words")
CSV_FIELDS = ("capture_id", "asset_id", "sequence", "tag", "value", "unit", "status_code",
              "source_timestamp", "server_timestamp", "received_timestamp", "unit_origin")
MAX_ROWS = 100_000
MAX_BYTES = 16 * 1024 * 1024
NANOSECONDS = 1_000_000_000
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


class AuditError(ValueError):
    pass


def _number(value, name):
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        raise AuditError(f"{name}: finite number required")
    try:
        result = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise AuditError(f"{name}: finite number required") from exc
    if not math.isfinite(result):
        raise AuditError(f"{name}: finite number required")
    return result


def _integer(value, name):
    if isinstance(value, bool) or not isinstance(value, (str, int)) or not re.fullmatch(r"[0-9]+", str(value)):
        raise AuditError(f"{name}: nonnegative integer required")
    result = int(value)
    if result > 2**63-1:
        raise AuditError(f"{name}: integer too large")
    return result


def _text(value, name):
    if not isinstance(value, str) or not value.strip() or len(value) > 256:
        raise AuditError(f"{name}: nonempty text required")
    return value.strip()


def timestamp(value):
    if not isinstance(value, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})", value
    ):
        raise AuditError("timestamp: timezone-aware ISO 8601 required")
    # Python 3.10 parses only 3- or 6-digit fractions; nanoseconds are kept separately.
    text = re.sub(r"\.(\d{1,9})", lambda m: "." + m.group(1)[:6].ljust(6, "0"), value.replace("Z", "+00:00"))
    try:
        return datetime.fromisoformat(text).astimezone(timezone.utc)
    except (ValueError, OverflowError) as exc:
        raise AuditError("timestamp: invalid date/time") from exc


def _timestamp_nanoseconds(value):
    """Exact supported UTC instant; datetime remains the date/offset validator."""
    parsed = timestamp(value)
    fraction = re.search(r"\.(\d{1,9})(?:Z|[+-]\d{2}:\d{2})$", value)
    nanoseconds = int(fraction.group(1).ljust(9, "0")) if fraction else 0
    whole = parsed.replace(microsecond=0) - EPOCH
    return (whole.days * 86400 + whole.seconds) * NANOSECONDS + nanoseconds


def _limit_nanoseconds(seconds):
    return int((Decimal(str(seconds)) * NANOSECONDS).to_integral_value(rounding=ROUND_FLOOR))


def _canonical_receiver_time(value):
    instant = _timestamp_nanoseconds(value)
    whole = timestamp(value).replace(microsecond=0).isoformat(timespec="seconds")
    return whole.removesuffix("+00:00") + f".{instant % NANOSECONDS:09d}+00:00"


def validate_profile(profile):
    allowed = {"schema", "asset_id", "freshness_basis", "quality_encoding", "max_age_seconds",
               "max_future_seconds", "max_snapshot_skew_seconds", "tags"}
    if (not isinstance(profile, dict) or set(profile) - allowed
            or (profile.get("schema") != SCHEMA and profile.get("schema") not in LEGACY_SCHEMAS)):
        raise AuditError("unsupported profile schema or fields")
    result = dict(profile)
    result["asset_id"] = _text(profile.get("asset_id"), "asset_id")
    if profile.get("freshness_basis") not in {"source", "server"}:
        raise AuditError("freshness_basis must explicitly be source or server")
    if profile.get("quality_encoding") not in QUALITY_ENCODINGS:
        raise AuditError("quality_encoding must explicitly be one of " + ", ".join(QUALITY_ENCODINGS))
    for key in ("max_age_seconds", "max_future_seconds", "max_snapshot_skew_seconds"):
        result[key] = _number(profile.get(key), key)
        if result[key] < 0 or (key != "max_future_seconds" and result[key] == 0):
            raise AuditError(f"{key}: invalid limit")
    tags = profile.get("tags")
    if not isinstance(tags, list) or not 1 <= len(tags) <= 64:
        raise AuditError("tags must contain 1 to 64 numeric channels")
    seen, normalized = set(), []
    for tag in tags:
        if not isinstance(tag, dict) or set(tag) - {"name", "unit", "minimum", "maximum", "source_node", "units_node"}:
            raise AuditError("invalid tag fields")
        item = dict(tag)
        item["name"] = _text(tag.get("name"), "tag.name")
        item["unit"] = _text(tag.get("unit"), "tag.unit")
        if item["name"] in seen:
            raise AuditError("duplicate tag name")
        seen.add(item["name"])
        for key in ("minimum", "maximum"):
            item[key] = None if tag.get(key) is None else _number(tag[key], key)
        if item["minimum"] is not None and item["maximum"] is not None and item["minimum"] >= item["maximum"]:
            raise AuditError("tag minimum must be below maximum")
        for key in ("source_node", "units_node"):
            if key in tag:
                item[key] = _text(tag[key], key)
        normalized.append(item)
    result["tags"] = normalized
    return result


def _da_quality_checks(value):
    """OPC Classic (DA) quality: the low byte is QQSSSSLL, so 192 (0xC0) is good and 0 is bad."""
    text = str(value).strip()
    if isinstance(value, bool) or not re.fullmatch(r"(?:0[xX][0-9a-fA-F]{1,4}|[0-9]{1,5})", text):
        return ["invalid_quality"], [], None
    code = int(text, 16 if text.lower().startswith("0x") else 10)
    if code > 0xFFFF or code & 0xC0 == 0x80:
        return ["invalid_quality"], [], None
    quality = code & 0xC0
    reasons = [] if quality == 0xC0 else ["quality_uncertain" if quality == 0x40 else "quality_bad"]
    warnings = ["local_override"] if code & 0xFC == 0xD8 else []
    if code & 0x03:
        warnings.append(("limit_low", "limit_high", "limit_constant")[(code & 0x03) - 1])
    return reasons, warnings, code


def status_checks(value, encoding):
    warnings = []
    if encoding == "opc_da_quality":
        return _da_quality_checks(value)
    if encoding == "quality_words":
        quality = str(value).strip().lower()
        if quality not in {"good", "uncertain", "bad"}:
            return ["invalid_quality"], [], None
        warnings.append("status_detail_unavailable")
        return ([] if quality == "good" else ["quality_"+quality]), warnings, None
    if isinstance(value, bool):
        return ["invalid_status_code"], [], None
    text = str(value).strip()
    try:
        if not re.fullmatch(r"(?:0[xX][0-9a-fA-F]{1,8}|[0-9]+)", text):
            raise ValueError
        code = int(text, 16 if text.lower().startswith("0x") else 10)
        if not 0 <= code <= 0xFFFFFFFF:
            raise ValueError
    except ValueError:
        return ["invalid_status_code"], [], None
    severity = code >> 30
    reasons = [] if severity == 0 else ["quality_uncertain" if severity == 1 else "quality_bad"]
    if code & 0xC000:
        reasons.append("metadata_changed_requires_review")
    if code & 0x30000000:
        reasons.append("reserved_status_bits")
    if code & 0x480 == 0x480:
        reasons.append("queue_overflow")
    if code and not reasons:
        warnings.append("nonzero_good_status_review")
    return reasons, warnings, code


def parse_csv(content, max_rows=MAX_ROWS, max_bytes=MAX_BYTES):
    if not isinstance(content, str) or len(content.encode("utf-8")) > max_bytes:
        raise AuditError("CSV exceeds the input size limit")
    try:
        reader = csv.DictReader(io.StringIO(content.lstrip("\ufeff")), strict=True)
        if not reader.fieldnames or len(set(reader.fieldnames)) != len(reader.fieldnames):
            raise AuditError("CSV header is missing or duplicated")
        if set(reader.fieldnames) != set(CSV_FIELDS):
            raise AuditError("CSV header must match the documented long-format fields")
        rows = []
        for row in reader:
            if None in row or any(value is None for value in row.values()):
                raise AuditError("CSV row has the wrong number of fields")
            rows.append(row)
            if len(rows) > max_rows:
                raise AuditError("CSV exceeds the row limit")
        return rows
    except csv.Error as exc:
        raise AuditError("malformed CSV") from exc


def audit_rows(profile, rows, max_rows=MAX_ROWS):
    profile = validate_profile(profile)
    tags = {tag["name"]: tag for tag in profile["tags"]}
    max_age_ns = _limit_nanoseconds(profile["max_age_seconds"])
    max_future_ns = _limit_nanoseconds(profile["max_future_seconds"])
    max_skew_ns = _limit_nanoseconds(profile["max_snapshot_skew_seconds"])
    results, snapshots = [], defaultdict(list)
    previous = {}
    for index, row in enumerate(rows, start=1):
        if index > max_rows:
            raise AuditError("row limit exceeded")
        if not isinstance(row, dict):
            raise AuditError("each row must be an object")
        reasons, warnings = [], []
        detail = {"row": index, "tag": str(row.get("tag", "")), "reasons": reasons, "warnings": warnings}
        try:
            capture = _text(row.get("capture_id"), "capture_id")
            sequence = _integer(row.get("sequence"), "sequence")
            asset = _text(row.get("asset_id"), "asset_id")
            tag_name = _text(row.get("tag"), "tag")
            if asset != profile["asset_id"]:
                reasons.append("asset_mismatch")
            tag = tags.get(tag_name)
            if tag is None:
                reasons.append("unknown_tag")
            elif str(row.get("unit", "")).strip() != tag["unit"]:
                reasons.append("unit_mismatch")
            try:
                value = _number(row.get("value"), "value")
                detail["value"] = value
                if tag and ((tag["minimum"] is not None and value < tag["minimum"])
                            or (tag["maximum"] is not None and value > tag["maximum"])):
                    reasons.append("outside_engineering_range")
            except AuditError:
                reasons.append("nonfinite_or_nonnumeric_value")
            quality_reasons, quality_warnings, code = status_checks(row.get("status_code"), profile["quality_encoding"])
            reasons.extend(quality_reasons)
            warnings.extend(quality_warnings)
            detail["status_code"] = code
            times = {}
            for key in ("source_timestamp", "server_timestamp", "received_timestamp"):
                try:
                    times[key] = _timestamp_nanoseconds(row.get(key))
                except AuditError:
                    reasons.append("invalid_"+key)
            if "received_timestamp" in times:
                received = times["received_timestamp"]
                detail["received_timestamp"] = _canonical_receiver_time(row["received_timestamp"])
                for kind in ("source", "server"):
                    ts = times.get(kind+"_timestamp")
                    if ts is not None:
                        age_ns = received-ts
                        age = age_ns / NANOSECONDS
                        detail[kind+"_age_seconds"] = age
                        detail[kind+"_age_nanoseconds"] = age_ns
                        if age_ns < -max_future_ns:
                            reasons.append(kind+"_timestamp_in_future")
                        if kind == profile["freshness_basis"] and age_ns > max_age_ns:
                            reasons.append("stale_"+kind+"_timestamp")
                if profile["freshness_basis"] == "server" and detail.get("source_age_nanoseconds", 0) > max_age_ns:
                    warnings.append("source_unchanged_or_old_check_server_provenance")
                key = (capture, asset, tag_name)
                old = previous.get(key)
                if old and sequence <= old[0]:
                    reasons.append("duplicate_or_reordered_sequence")
                if old and received < old[1]:
                    reasons.append("receiver_time_went_backwards")
                previous[key] = (max(sequence, old[0] if old else sequence), max(received, old[1] if old else received))
            origin = str(row.get("unit_origin", "")).strip()
            detail["unit_origin"] = origin
            if origin not in {"server_property", "export_field"}:
                reasons.append("unit_provenance_missing")
            if origin == "export_field":
                warnings.append("unit_is_export_declaration")
            detail.update({"capture_id": capture, "sequence": sequence, "asset_id": asset, "tag": tag_name})
            snapshots[(capture, sequence)].append(detail)
        except AuditError:
            reasons.append("malformed_record_identity")
        detail["passed"] = not reasons
        results.append(detail)
    snapshot_results = []
    for (capture, sequence), entries in snapshots.items():
        counts = Counter(entry["tag"] for entry in entries)
        missing = sorted(set(tags)-set(counts))
        duplicates = sorted(tag for tag, count in counts.items() if count > 1)
        received = [_timestamp_nanoseconds(entry["received_timestamp"]) for entry in entries if "received_timestamp" in entry]
        skew_ns = max(received)-min(received) if received else None
        skew = skew_ns / NANOSECONDS if skew_ns is not None else None
        coherent = skew_ns is not None and skew_ns <= max_skew_ns
        snapshot_results.append({"capture_id": capture, "sequence": sequence, "missing_tags": missing,
            "duplicate_tags": duplicates, "received_skew_seconds": skew,
            "received_skew_nanoseconds": skew_ns, "skew_within_limit": coherent,
            "passed": not missing and not duplicates and coherent and all(entry["passed"] for entry in entries)})
    passed = sum(row["passed"] for row in results)
    unbounded = [tag["name"] for tag in profile["tags"] if tag["minimum"] is None and tag["maximum"] is None]
    not_evaluated = ([{"check": "engineering_range", "tags": unbounded, "reason": "no minimum or maximum declared"}]
                     if unbounded else [])
    return {"schema": REPORT_SCHEMA, "asset_id": profile["asset_id"], "not_evaluated": not_evaluated,
        "profile_sha256": hashlib.sha256(json.dumps(profile, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest(),
        "time_basis": "recorded receiver timestamps; not a claim about current live freshness",
        "freshness_basis": profile["freshness_basis"], "rows": results, "snapshots": snapshot_results,
        "summary": {"rows": len(results), "passed_rows": passed, "rejected_rows": len(results)-passed,
            "snapshots": len(snapshot_results), "passed_snapshots": sum(x["passed"] for x in snapshot_results),
            "reason_counts": dict(Counter(reason for row in results for reason in row["reasons"])),
            "checks_passed": bool(results) and passed == len(results) and bool(snapshot_results) and all(x["passed"] for x in snapshot_results)},
        "scope": "metadata/profile contract checks; no sensor-correctness, authenticated-source, model-calibration or actuation claim"}


def audit_csv(profile, content, max_rows=MAX_ROWS, max_bytes=MAX_BYTES):
    if not isinstance(content, str):
        raise AuditError("CSV must be decoded text")
    content = content.lstrip("\ufeff")
    report = audit_rows(profile, parse_csv(content, max_rows, max_bytes), max_rows)
    report["csv_sha256"] = hashlib.sha256(content.encode("utf-8")).hexdigest()
    report["hash_basis"] = "UTF-8 decoded CSV text with leading BOM removed, original line endings; canonical normalized profile JSON"
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description="Audit engineering-unit telemetry locally; no network connection.")
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--csv", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.csv.stat().st_size > MAX_BYTES or args.profile.stat().st_size > 256_000:
            raise AuditError("input file exceeds the size limit")
        profile = json.loads(args.profile.read_text(encoding="utf-8"))
        raw = args.csv.read_bytes()
        report = audit_csv(profile, raw.decode("utf-8-sig"))
        report["input_file_sha256"] = hashlib.sha256(raw).hexdigest()
        args.output.write_text(json.dumps(report, indent=2, allow_nan=False), encoding="utf-8")
        print(json.dumps(report["summary"]))
        return 0 if report["summary"]["checks_passed"] else 2
    except (AuditError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        parser.exit(1, f"Audit failed: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
