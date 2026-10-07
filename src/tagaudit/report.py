"""Turn audit reports into plain language, and trim them for saving."""
from __future__ import annotations

import textwrap
from collections import Counter

from . import __version__

REASONS = {
    "unit_mismatch": "unit differs from the profile",
    "outside_engineering_range": "value outside the declared range",
    "nonfinite_or_nonnumeric_value": "value is not a number",
    "quality_bad": "quality code says bad",
    "quality_uncertain": "quality code says uncertain",
    "invalid_quality": "quality code can't be read",
    "invalid_status_code": "status code can't be read",
    "metadata_changed_requires_review": "server flagged a metadata change",
    "queue_overflow": "server dropped queued values",
    "reserved_status_bits": "status code uses reserved bits",
    "unknown_tag": "tag isn't in the profile",
    "asset_mismatch": "asset differs from the profile",
    "unit_provenance_missing": "no record of where the unit came from",
    "stale_server_timestamp": "server timestamp older than the freshness limit",
    "stale_source_timestamp": "source timestamp older than the freshness limit",
    "source_timestamp_in_future": "source timestamp ahead of the receive time",
    "server_timestamp_in_future": "server timestamp ahead of the receive time",
    "invalid_source_timestamp": "source timestamp can't be read",
    "invalid_server_timestamp": "server timestamp can't be read",
    "invalid_received_timestamp": "receive timestamp can't be read",
    "duplicate_or_reordered_sequence": "sample sequence repeated or out of order",
    "receiver_time_went_backwards": "receive time went backwards",
    "malformed_record_identity": "capture, asset, tag or sequence is malformed",
    "invalid_timestamp": "timestamp can't be read",
    "duplicate_timestamp": "same tag twice at the same time",
    "timestamp_went_backwards": "earlier than this tag's previous value",
    "gap_exceeds_limit": "gap since the previous value exceeds max_gap_seconds",
    "stuck_value": "value unchanged for more than max_repeats samples",
    "ambiguous_local_time": "local time happens twice (clocks went back)",
    "nonexistent_local_time": "local time never happened (clocks went forward)",
    "malformed_row": "row has the wrong number of fields",
}

WARNINGS = {
    "source_unchanged_or_old_check_server_provenance": "source timestamp is old while the server timestamp is fresh",
    "status_detail_unavailable": "quality words hide the detailed status",
    "nonzero_good_status_review": "good status with extra bits set",
    "unit_is_export_declaration": "unit comes from the export, not the server",
    "local_override": "quality says a local override is active",
    "limit_low": "value held at a low limit",
    "limit_high": "value held at a high limit",
    "limit_constant": "value marked constant",
}

FORMATS = {"native": "native capture", "long": "long export", "wide": "wide export"}


def finalize(report, *, examples, full, source, input_sha256):
    """Add examples and provenance; drop per-row detail unless `full`."""
    result = dict(report)
    if "examples" not in result:  # native reports carry every row; derive the same shape as exports
        found = {}
        for row in result["rows"]:
            row.setdefault("line", row["row"] + 1)
            for reason in row["reasons"]:
                found.setdefault(reason, [])
                if len(found[reason]) < examples:
                    found[reason].append(row)
        result["examples"] = found
        result["group_examples"] = [group for group in result["snapshots"] if not group["passed"]][:examples]
        missing = Counter(name for group in result["snapshots"] for name in group["missing_tags"])
        result["summary"] = {**result["summary"], "missing_by_tag": dict(missing), "warning_counts": dict(
            Counter(warning for row in result["rows"] for warning in row["warnings"]))}
        result.setdefault("input_format", "native")
    if not full:
        result.pop("rows", None)
        result.pop("snapshots", None)
    result.update(source=source, input_file_sha256=input_sha256, tagaudit_version=__version__)
    return result


def _names(names, limit=7):
    shown = ", ".join(names[:limit])
    return shown + (f" and {len(names) - limit} more" if len(names) > limit else "")


def _where(item):
    stamp = item.get("timestamp") or item.get("received_timestamp", "")
    return f"line {item['line']}  {item['tag']} = {item.get('value', '')}" + (f"  at {stamp}" if stamp else "")


def _group(item):
    """Wide rows have a line, native groups a sequence, synchronized long groups only a timestamp."""
    if "line" in item:
        label = f"line {item['line']}"
    elif "sequence" in item:
        label = f"sequence {item['sequence']}"
    else:
        label = ""
    if item.get("timestamp"):
        label = f"{label}  {item['timestamp']}" if label else item["timestamp"]
    parts = []
    if item.get("missing_tags"):
        parts.append("missing " + _names(item["missing_tags"]))
    if item.get("duplicate_tags"):
        parts.append("repeated " + _names(item["duplicate_tags"]))
    if item.get("skew_within_limit") is False and item.get("received_skew_seconds") is not None:
        parts.append(f"values received {item['received_skew_seconds']:g} s apart, over the skew limit")
    return f"  {label}  " + ("; ".join(parts) or "contains rejected values")


def render_text(report, *, notes=(), output=None):
    summary = report["summary"]
    head = [f"tagaudit {__version__}", report.get("source", ""), FORMATS.get(report.get("input_format"), "")]
    if report.get("asset_id"):
        head.append(f"asset {report['asset_id']}")
    lines = [" · ".join(part for part in head if part)]
    span = report.get("time_span")
    if span:
        lines.append(f"{span['first']} to {span['last']} ({span['basis']})")
    rows, rejected = summary["rows"], summary["rejected_rows"]
    groups, failed_groups = summary["snapshots"], summary["snapshots"] - summary["passed_snapshots"]
    if summary["checks_passed"]:
        verdict = f"PASS  {rows} values passed"
        verdict += f" · {groups} sample groups complete" if groups else ""
    else:
        verdict = f"FAIL  {rejected} of {rows} values rejected"
        verdict += f" · {failed_groups} of {groups} sample groups incomplete or failing" if groups else ""
    lines += ["", verdict]

    if summary["reason_counts"]:
        lines += ["", "Problems"]
        for reason, count in sorted(summary["reason_counts"].items(), key=lambda item: (-item[1], item[0])):
            lines.append(f"  {reason:<32} {count:>6}  {REASONS.get(reason, '')}")
            lines += [f"      {_where(item)}" for item in report["examples"].get(reason, [])[:3]]
    missing = summary.get("missing_by_tag") or {}
    if missing:
        lines += ["", f"Missing values (out of {groups} sample groups)"]
        always = [name for name, count in missing.items() if count == groups]
        if always:
            label = f"  always empty ({len(always)} tag{'s' if len(always) != 1 else ''})  "
            lines += textwrap.wrap(", ".join(always), width=100, initial_indent=label,
                                   subsequent_indent=" " * len(label), break_on_hyphens=False)
        for name, count in sorted(missing.items(), key=lambda item: (-item[1], item[0])):
            if count != groups:
                lines.append(f"  {name:<32} {count:>6}  ({count / groups:.1%})")
    if report.get("group_examples"):
        lines += ["", "Incomplete or failing sample groups"]
        lines += [_group(item) for item in report["group_examples"]]
    if summary.get("warning_counts"):
        lines += ["", "Warnings"]
        for warning, count in sorted(summary["warning_counts"].items(), key=lambda item: (-item[1], item[0])):
            lines.append(f"  {warning:<32} {count:>6}  {WARNINGS.get(warning, '')}")
    if report.get("not_evaluated"):
        lines += ["", "Not checked"]
        for item in report["not_evaluated"]:
            tags = f" ({_names(item['tags'])})" if item.get("tags") else ""
            lines.append(f"  {item['check']:<28} {item['reason']}{tags}")
    for note in notes:
        lines += ["", note]
    if output:
        lines += ["", f"Report written to {output}"]
    return "\n".join(lines)
