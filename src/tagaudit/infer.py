"""Write a starter profile from an export.

It records the layout, tag names and the units seen in the file. Ranges, the quality
encoding and the time zone are left for a person to declare, because guessing them
would make those checks prove nothing.
"""
from __future__ import annotations

import csv
from collections import Counter

from .audit import SCHEMA, AuditError
from .series import MAX_TAGS, detect_format, parse_time


def _timestamp_format(sample):
    if sample is None or parse_time(sample, "iso", None)[0] is not None:
        return "iso", None
    try:
        number = float(sample)
    except ValueError:
        return "iso", ("Timestamps aren't ISO 8601: set input.timestamp_format to a strptime pattern "
                       "such as %d/%m/%Y %H:%M:%S.")
    return ("epoch_ms" if abs(number) > 1e11 else "epoch_s"), None


def infer_profile(stream, *, asset_id=None, quality_encoding=None, timezone=None):
    """Return (profile, notes). Notes tell the user what to declare next."""
    reader = csv.reader(stream, strict=True)
    try:
        header = [name.strip() for name in next(reader)]
    except StopIteration:
        raise AuditError("the export is empty") from None
    except csv.Error as exc:
        raise AuditError(f"malformed CSV header: {exc}") from exc
    layout = detect_format(header)
    if layout["format"] == "native":
        raise AuditError("this is a native capture; check it with the profile it was collected with (--profile PROFILE)")
    at = {name: index for index, name in enumerate(header)}
    sample, order, units = None, [], {}
    try:
        for cells in reader:
            if len(cells) != len(header) or not any(cell.strip() for cell in cells):
                continue
            sample = sample or cells[at[layout["timestamp"]]].strip()
            if layout["format"] == "wide":
                break
            name = cells[at[layout["tag"]]].strip()
            if name and name not in units:
                if len(order) == MAX_TAGS:
                    raise AuditError(f"more than {MAX_TAGS} tags; split the export")
                order.append(name)
                units[name] = Counter()
            if name and "unit" in layout and cells[at[layout["unit"]]].strip():
                units[name][cells[at[layout["unit"]]].strip()] += 1
    except csv.Error as exc:
        raise AuditError(f"malformed CSV near line {reader.line_num}: {exc}") from exc
    if layout["format"] == "wide":
        order = list(layout["columns"])
    if not order:
        raise AuditError("no tag values found in the export")

    fmt, format_note = _timestamp_format(sample)
    tags, notes = [], []
    for name in order:
        tag = {"name": name}
        if units.get(name):
            tag["unit"] = units[name].most_common(1)[0][0]
            if len(units[name]) > 1:
                notes.append(f"{name} uses more than one unit in the export ({', '.join(sorted(units[name]))}); "
                             f"wrote the most common one.")
        tags.append(tag)
    spec = {key: value for key, value in layout.items() if key != "columns"}
    spec.update(timezone=timezone, timestamp_format=fmt)
    profile = {"schema": SCHEMA}
    if asset_id:
        profile["asset_id"] = asset_id
    profile.update(quality_encoding=quality_encoding, input=spec, tags=tags)

    notes.insert(0, f"Found {len(tags)} tags in a {layout['format']} export.")
    notes.append("Add minimum and maximum to each tag to check engineering ranges.")
    if "quality" in layout and quality_encoding is None:
        notes.append(f"Quality column '{layout['quality']}' found: set quality_encoding to opcua_status_code, "
                     "opc_da_quality (192 = good) or quality_words. tagaudit won't guess it.")
    if format_note:
        notes.append(format_note)
    elif sample and timezone is None and fmt == "iso" and parse_time(sample, "iso", None)[2]:
        notes.append("Timestamps have no UTC offset: set input.timezone (UTC, +04:00 or a zone such as "
                     "Europe/Berlin) to catch daylight-saving problems.")
    notes.append("Optional: set max_gap_seconds and max_repeats to find gaps and stuck values.")
    return profile, notes
