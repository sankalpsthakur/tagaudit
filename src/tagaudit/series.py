"""Historian and generic CSV exports: long (timestamp, tag, value) or wide (one column per tag).

Exports carry less evidence than a native capture. Each check runs only when the export
and profile supply what it needs; everything else is listed in the report's
``not_evaluated`` section instead of being guessed. Rows are streamed, so memory stays
bounded by the number of tags, not the length of the file.
"""
from __future__ import annotations

import csv
import hashlib
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation

from .audit import (CSV_FIELDS, EPOCH, LEGACY_SCHEMAS, NANOSECONDS, QUALITY_ENCODINGS, REPORT_SCHEMA, SCHEMA,
                    AuditError, _number, _text, status_checks)

MAX_TAGS = 5000
DEFAULT_EXAMPLES = 5

TIME_NAMES = ("timestamp", "time", "t_stamp", "_time", "datetime", "date_time", "ts", "date")
TAG_NAMES = ("tag", "tagname", "tag_name", "tagpath", "tag_path", "name", "point", "pointname",
             "item", "itemid", "signal", "variable", "_field")
VALUE_NAMES = ("value", "val", "_value", "pv")
QUALITY_NAMES = ("quality", "quality_code", "status", "statuscode", "status_code", "q")
UNIT_NAMES = ("unit", "units", "eu", "engunits", "eng_units", "uom")

ISO_TIME = re.compile(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}(?::\d{2})?)(?:\.(\d{1,9}))?\s*(Z|[+-]\d{2}:?\d{2})?")


def _find(header, names):
    lowered = {name.strip().lower(): name.strip() for name in header}
    return next((lowered[name] for name in names if name in lowered), None)


def detect_format(header):
    """Guess how an export is laid out from its header. Used by `init` and profile-less checks."""
    cleaned = [name.strip() for name in header]
    if set(cleaned) == set(CSV_FIELDS):
        return {"format": "native"}
    stamp = _find(cleaned, TIME_NAMES)
    if stamp is None:
        parts = [name for name in cleaned
                 if re.search(r"(^|[_\-\s])(year|month|day|hour|minute|second)s?($|[_\-\s])", name.lower())]
        if len(parts) >= 2:
            raise AuditError("no timestamp column found: this export seems to split date and time across several "
                             f"columns ({', '.join(parts[:3])}...), which tagaudit doesn't support yet. It needs one "
                             "column with the full date and time.")
        raise AuditError("no timestamp column found; tagaudit needs one column with the full date and time. "
                         "Name it in the profile as input.timestamp.")
    tag, value = _find(cleaned, TAG_NAMES), _find(cleaned, VALUE_NAMES)
    if tag and value:
        layout = {"format": "long", "timestamp": stamp, "tag": tag, "value": value}
        for key, names in (("quality", QUALITY_NAMES), ("unit", UNIT_NAMES)):
            column = _find(cleaned, names)
            if column:
                layout[key] = column
        return layout
    columns = [name for name in cleaned if name != stamp]
    if not columns:
        raise AuditError("no tag columns found next to the timestamp column")
    return {"format": "wide", "timestamp": stamp, "columns": columns}


def _zone(text):
    if text is None:
        return None
    value = _text(text, "input.timezone")
    if value.upper() in {"UTC", "Z"}:
        return timezone.utc
    offset = re.fullmatch(r"([+-])(\d{2}):?(\d{2})", value)
    if offset:
        sign = 1 if offset.group(1) == "+" else -1
        return timezone(sign * timedelta(hours=int(offset.group(2)), minutes=int(offset.group(3))))
    try:
        from zoneinfo import ZoneInfo
        return ZoneInfo(value)
    except (KeyError, ValueError, OSError) as exc:
        raise AuditError(f"unknown timezone: {value}") from exc


def _optional_positive(value, name, integer=False):
    if value is None:
        return None
    if integer:
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise AuditError(f"{name}: positive integer required")
        return value
    number = _number(value, name)
    if number <= 0:
        raise AuditError(f"{name}: positive number required")
    return number


def validate_series_profile(profile):
    allowed = {"schema", "asset_id", "quality_encoding", "tags", "input", "max_gap_seconds", "max_repeats"}
    if (not isinstance(profile, dict) or set(profile) - allowed
            or (profile.get("schema") != SCHEMA and profile.get("schema") not in LEGACY_SCHEMAS)):
        raise AuditError("unsupported profile schema or fields")
    result = {"schema": profile["schema"]}
    if profile.get("asset_id") is not None:
        result["asset_id"] = _text(profile["asset_id"], "asset_id")
    encoding = profile.get("quality_encoding")
    if encoding is not None and encoding not in QUALITY_ENCODINGS:
        raise AuditError("quality_encoding must be one of " + ", ".join(QUALITY_ENCODINGS))
    result["quality_encoding"] = encoding
    result["max_gap_seconds"] = _optional_positive(profile.get("max_gap_seconds"), "max_gap_seconds")
    result["max_repeats"] = _optional_positive(profile.get("max_repeats"), "max_repeats", integer=True)
    tags = profile.get("tags")
    if not isinstance(tags, list) or not 1 <= len(tags) <= MAX_TAGS:
        raise AuditError(f"tags must contain 1 to {MAX_TAGS} entries")
    seen, normalized = set(), []
    for tag in tags:
        if not isinstance(tag, dict) or set(tag) - {"name", "unit", "minimum", "maximum", "max_gap_seconds",
                                                    "max_repeats", "description"}:
            raise AuditError("invalid tag fields")
        item = {"name": _text(tag.get("name"), "tag.name")}
        if item["name"] in seen:
            raise AuditError(f"duplicate tag name: {item['name']}")
        seen.add(item["name"])
        item["unit"] = None if tag.get("unit") is None else _text(tag["unit"], "tag.unit")
        for key in ("minimum", "maximum"):
            item[key] = None if tag.get(key) is None else _number(tag[key], key)
        if item["minimum"] is not None and item["maximum"] is not None and item["minimum"] >= item["maximum"]:
            raise AuditError(f"{item['name']}: minimum must be below maximum")
        item["max_gap_seconds"] = _optional_positive(tag.get("max_gap_seconds"), "max_gap_seconds")
        item["max_repeats"] = _optional_positive(tag.get("max_repeats"), "max_repeats", integer=True)
        normalized.append(item)
    result["tags"] = normalized
    result["input"] = _validate_input(profile.get("input"), [tag["name"] for tag in normalized])
    return result


def _validate_input(spec, tag_names):
    """tag_names keeps profile order, which is also the order wide columns are read in."""
    keys = {"format", "timestamp", "tag", "value", "quality", "unit", "columns", "timezone",
            "timestamp_format", "synchronized"}
    if not isinstance(spec, dict) or set(spec) - keys or spec.get("format") not in {"long", "wide"}:
        raise AuditError("input must declare format long or wide, with known fields only")
    result = {"format": spec["format"], "timestamp": _text(spec.get("timestamp"), "input.timestamp")}
    if spec["format"] == "long":
        result["tag"] = _text(spec.get("tag"), "input.tag")
        result["value"] = _text(spec.get("value"), "input.value")
        for key in ("quality", "unit"):
            result[key] = None if spec.get(key) is None else _text(spec[key], "input." + key)
        if not isinstance(spec.get("synchronized", False), bool):
            raise AuditError("input.synchronized must be true or false")
        result["synchronized"] = spec.get("synchronized", False)
    else:
        if {"tag", "value", "quality", "unit", "synchronized"} & set(spec):
            raise AuditError("wide exports map tags with input.columns")
        columns = spec.get("columns", {})
        if not isinstance(columns, dict) or set(columns) - set(tag_names):
            raise AuditError("input.columns must map declared tag names to column names")
        result["columns"] = {name: _text(columns.get(name, name), "input.columns") for name in tag_names}
    result["timezone"] = spec.get("timezone")
    _zone(result["timezone"])
    fmt = spec.get("timestamp_format", "iso")
    if not isinstance(fmt, str) or (fmt not in {"iso", "epoch_s", "epoch_ms"} and "%" not in fmt):
        raise AuditError("timestamp_format must be iso, epoch_s, epoch_ms or a strptime pattern")
    result["timestamp_format"] = fmt
    return result


def _localize(naive, zone):
    first, second = naive.replace(tzinfo=zone, fold=0), naive.replace(tzinfo=zone, fold=1)
    if first.utcoffset() == second.utcoffset():
        return first, None
    back = first.astimezone(timezone.utc).astimezone(zone).replace(tzinfo=None)
    return None, "nonexistent_local_time" if back != naive else "ambiguous_local_time"


def parse_time(text, fmt, zone):
    """Return (nanoseconds since the epoch, problem, naive). Naive times without a zone stay wall-clock."""
    text = text.strip()
    extra_ns = 0
    try:
        if fmt in {"epoch_s", "epoch_ms"}:
            number = Decimal(text)
            if not number.is_finite():
                return None, "invalid_timestamp", False
            return int(number * (NANOSECONDS if fmt == "epoch_s" else 1_000_000)), None, False
        if fmt == "iso":
            match = ISO_TIME.fullmatch(text)
            if not match:
                return None, "invalid_timestamp", False
            day, clock, fraction, offset = match.groups()
            fraction = fraction or ""
            extra_ns = int(fraction[6:].ljust(3, "0")) if len(fraction) > 6 else 0
            # Python 3.10 parses only 3- or 6-digit fractions; extra digits are kept in extra_ns.
            stamp = datetime.fromisoformat(f"{day}T{clock}" + (f".{fraction[:6].ljust(6, '0')}" if fraction else ""))
            if offset:
                offset = "+00:00" if offset == "Z" else offset if ":" in offset else f"{offset[:3]}:{offset[3:]}"
                stamp = stamp.replace(tzinfo=datetime.fromisoformat("2000-01-01T00:00:00" + offset).tzinfo)
        else:
            stamp = datetime.strptime(text, fmt)
        naive = stamp.tzinfo is None
        if naive and zone is not None:
            stamp, problem = _localize(stamp, zone)
            if problem:
                return None, problem, False
        elif naive:
            stamp = stamp.replace(tzinfo=timezone.utc)
        delta = stamp - EPOCH
        return (delta.days * 86400 + delta.seconds) * NANOSECONDS + delta.microseconds * 1000 + extra_ns, None, naive
    except (ValueError, OverflowError, InvalidOperation):
        return None, "invalid_timestamp", False


def _iso(nanoseconds, utc):
    """UTC instants end in Z; wall-clock times with no declared offset get no suffix."""
    stamp = (EPOCH + timedelta(microseconds=nanoseconds // 1000)).isoformat()
    return stamp.replace("+00:00", "Z") if utc else stamp.removesuffix("+00:00")


class _Tally:
    """Counts every outcome and keeps only the first few examples of each problem."""

    def __init__(self, examples, keep_rows):
        self.examples_per_reason = examples
        self.examples = defaultdict(list)
        self.group_examples = []
        self.reasons, self.warnings = Counter(), Counter()
        self.rows = self.passed = self.groups = self.passed_groups = 0
        self.kept_rows = [] if keep_rows else None
        self.kept_groups = [] if keep_rows else None

    def row(self, detail):
        detail["passed"] = not detail["reasons"]
        self.rows += 1
        self.passed += detail["passed"]
        self.reasons.update(detail["reasons"])
        self.warnings.update(detail["warnings"])
        for reason in detail["reasons"]:
            if len(self.examples[reason]) < self.examples_per_reason:
                self.examples[reason].append(detail)
        if self.kept_rows is not None:
            self.kept_rows.append(detail)

    def group(self, detail):
        self.groups += 1
        self.passed_groups += detail["passed"]
        if not detail["passed"] and len(self.group_examples) < self.examples_per_reason:
            self.group_examples.append(detail)
        if self.kept_groups is not None:
            self.kept_groups.append(detail)


def audit_series(profile, stream, *, examples=DEFAULT_EXAMPLES, detail="examples", max_rows=None):
    """Audit a long or wide CSV export read from a text stream (open the file with newline="")."""
    profile = validate_series_profile(profile)
    spec, tags = profile["input"], {tag["name"]: tag for tag in profile["tags"]}
    zone = _zone(spec["timezone"])
    tally = _Tally(examples, detail == "full")
    reader = csv.reader(stream, strict=True)
    try:
        header = [name.strip() for name in next(reader)]
    except StopIteration:
        raise AuditError("the export is empty") from None
    except csv.Error as exc:
        raise AuditError(f"malformed CSV header: {exc}") from exc
    if header and header[0].startswith("﻿"):
        header[0] = header[0][1:]
    if len(set(header)) != len(header):
        raise AuditError("the export header repeats a column name")
    needed = ([spec["timestamp"], spec["tag"], spec["value"]] + [spec[k] for k in ("quality", "unit") if spec[k]]
              if spec["format"] == "long" else [spec["timestamp"], *spec["columns"].values()])
    missing = [name for name in needed if name not in header]
    if missing:
        raise AuditError("columns named in the profile are missing from the export: " + ", ".join(missing))
    at = {name: index for index, name in enumerate(header)}
    state = {name: {"time": None, "value": None, "repeats": 0} for name in tags}
    groups = {}  # synchronized long exports: timestamp -> group detail
    missing_by_tag = Counter()
    seen = {"naive": False, "first": None, "last": None}

    def check_value(detail, tag, value_text, unit_text, quality_text):
        reasons, warnings = detail["reasons"], detail["warnings"]
        if unit_text is not None and tag["unit"] is not None and unit_text.strip() != tag["unit"]:
            reasons.append("unit_mismatch")
        try:
            value = _number(value_text, "value")
        except AuditError:
            reasons.append("nonfinite_or_nonnumeric_value")
            value = None
        if value is not None and ((tag["minimum"] is not None and value < tag["minimum"])
                                  or (tag["maximum"] is not None and value > tag["maximum"])):
            reasons.append("outside_engineering_range")
        if quality_text is not None and profile["quality_encoding"]:
            quality_reasons, quality_warnings, _ = status_checks(quality_text, profile["quality_encoding"])
            reasons.extend(quality_reasons)
            warnings.extend(quality_warnings)
        return value

    def check_time(detail, tag, instant, value):
        memory = state[tag["name"]]
        previous = memory["time"]
        if previous is not None:
            if instant == previous:
                detail["reasons"].append("duplicate_timestamp")
            elif instant < previous:
                detail["reasons"].append("timestamp_went_backwards")
            else:
                limit = tag["max_gap_seconds"] or profile["max_gap_seconds"]
                gap = instant - previous
                if limit is not None and gap > round(limit * NANOSECONDS):
                    detail["reasons"].append("gap_exceeds_limit")
                    detail["gap_seconds"] = gap / NANOSECONDS
        memory["time"] = instant if previous is None else max(previous, instant)
        if value is not None:
            limit = tag["max_repeats"] or profile["max_repeats"]
            memory["repeats"] = memory["repeats"] + 1 if value == memory["value"] else 0
            memory["value"] = value
            if limit is not None and memory["repeats"] > limit:
                detail["reasons"].append("stuck_value")

    def timestamp_of(text):
        instant, problem, naive = parse_time(text, spec["timestamp_format"], zone)
        if instant is not None:
            seen["naive"] = seen["naive"] or naive
            seen["first"] = instant if seen["first"] is None else min(seen["first"], instant)
            seen["last"] = instant if seen["last"] is None else max(seen["last"], instant)
        return instant, problem

    for row_number, cells in enumerate(_rows(reader), start=1):
        line = reader.line_num
        if max_rows is not None and row_number > max_rows:
            raise AuditError(f"row limit of {max_rows} exceeded; raise it with --max-rows")
        if len(cells) != len(header):
            tally.row({"row": row_number, "line": line, "tag": "", "value": "", "timestamp": "",
                       "reasons": ["malformed_row"], "warnings": []})
            continue
        stamp_text = cells[at[spec["timestamp"]]]
        instant, time_problem = timestamp_of(stamp_text)
        if spec["format"] == "long":
            name = cells[at[spec["tag"]]].strip()
            detail = {"row": row_number, "line": line, "tag": name, "value": cells[at[spec["value"]]],
                      "timestamp": stamp_text, "reasons": [], "warnings": []}
            tag = tags.get(name)
            if time_problem:
                detail["reasons"].append(time_problem)
            if tag is None:
                detail["reasons"].append("unknown_tag")
            else:
                unit = cells[at[spec["unit"]]] if spec["unit"] else None
                quality = cells[at[spec["quality"]]] if spec["quality"] else None
                value = check_value(detail, tag, detail["value"], unit, quality)
                if instant is not None:
                    check_time(detail, tag, instant, value)
            tally.row(detail)
            if spec["synchronized"] and instant is not None:
                group = groups.setdefault(instant, {"timestamp": stamp_text, "tags": Counter(), "passed": True})
                group["tags"][name] += 1
                group["passed"] = group["passed"] and detail["passed"]
            continue
        group_passed, absent = True, []
        for name, column in spec["columns"].items():
            text = cells[at[column]]
            if not text.strip():
                absent.append(name)
                missing_by_tag[name] += 1
                continue
            detail = {"row": row_number, "line": line, "tag": name, "value": text, "timestamp": stamp_text,
                      "reasons": [], "warnings": []}
            if time_problem:
                detail["reasons"].append(time_problem)
            value = check_value(detail, tags[name], text, None, None)
            if instant is not None:
                check_time(detail, tags[name], instant, value)
            tally.row(detail)
            group_passed = group_passed and detail["passed"]
        tally.group({"line": line, "timestamp": stamp_text, "missing_tags": absent, "duplicate_tags": [],
                     "passed": group_passed and not absent})
    for group in groups.values():
        missing = sorted(set(tags) - set(group["tags"]))
        missing_by_tag.update(missing)
        duplicates = sorted(name for name, count in group["tags"].items() if count > 1)
        tally.group({"timestamp": group["timestamp"], "missing_tags": missing, "duplicate_tags": duplicates,
                     "passed": group["passed"] and not missing and not duplicates})

    wall_clock = seen["naive"] and zone is None
    report = {
        "schema": REPORT_SCHEMA,
        "input_format": spec["format"],
        "asset_id": profile.get("asset_id"),
        "profile_sha256": hashlib.sha256(json.dumps(profile, sort_keys=True, separators=(",", ":"),
                                                    allow_nan=False).encode()).hexdigest(),
        "not_evaluated": _not_evaluated(profile, wall_clock),
        "time_span": None if seen["first"] is None else {
            "first": _iso(seen["first"], not wall_clock), "last": _iso(seen["last"], not wall_clock),
            "basis": "local wall clock, no UTC offset declared" if wall_clock else "UTC"},
        "summary": {
            "rows": tally.rows, "passed_rows": tally.passed, "rejected_rows": tally.rows - tally.passed,
            "snapshots": tally.groups, "passed_snapshots": tally.passed_groups,
            "reason_counts": dict(tally.reasons), "warning_counts": dict(tally.warnings),
            "missing_by_tag": {name: missing_by_tag[name] for name in tags if missing_by_tag[name]},
            "checks_passed": tally.rows > 0 and tally.passed == tally.rows and tally.passed_groups == tally.groups,
        },
        "examples": dict(tally.examples),
        "group_examples": tally.group_examples,
        "scope": "export contract checks; no sensor-correctness, live-freshness, calibration or actuation claim",
    }
    if tally.kept_rows is not None:
        report["rows"], report["snapshots"] = tally.kept_rows, tally.kept_groups
    return report


def _rows(reader):
    try:
        for cells in reader:
            if cells and any(cell.strip() for cell in cells):
                yield cells
    except csv.Error as exc:
        raise AuditError(f"malformed CSV near line {reader.line_num}: {exc}") from exc


def _not_evaluated(profile, naive_without_zone):
    spec, tags = profile["input"], profile["tags"]
    items: list[dict] = [{"check": "freshness",
                          "reason": "exports carry no receive time, so data age at the edge is unknown"}]
    if spec["format"] == "wide" or spec["unit"] is None:
        items.append({"check": "units", "reason": "the export has no unit column"})
    elif any(tag["unit"] is None for tag in tags):
        items.append({"check": "units", "tags": [t["name"] for t in tags if t["unit"] is None],
                      "reason": "no unit declared"})
    if spec["format"] == "wide" or spec["quality"] is None:
        items.append({"check": "quality", "reason": "the export has no quality column"})
    elif profile["quality_encoding"] is None:
        items.append({"check": "quality", "reason": "quality column present but quality_encoding is not declared"})
    unbounded = [tag["name"] for tag in tags if tag["minimum"] is None and tag["maximum"] is None]
    if unbounded:
        items.append({"check": "engineering_range", "tags": unbounded, "reason": "no minimum or maximum declared"})
    for check, key in (("gaps", "max_gap_seconds"), ("stuck_values", "max_repeats")):
        unset = [] if profile[key] is not None else [tag["name"] for tag in tags if tag[key] is None]
        if len(unset) == len(tags):
            items.append({"check": check, "reason": f"no {key} declared"})
        elif unset:
            items.append({"check": check, "tags": unset, "reason": f"no {key} declared"})
    if spec["format"] == "long" and not spec["synchronized"]:
        items.append({"check": "sample_groups", "reason": "long export is not declared synchronized"})
    if naive_without_zone:
        items.append({"check": "daylight_saving_and_offsets",
                      "reason": "timestamps have no UTC offset and input.timezone is not declared"})
    return items
