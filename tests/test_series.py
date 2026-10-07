import io

import pytest
from tagaudit.audit import AuditError
from tagaudit.series import audit_series, detect_format


def long_profile(**extra):
    profile = {"schema": "tagaudit.profile.v1", "quality_encoding": "opc_da_quality",
        "input": {"format": "long", "timestamp": "Time", "tag": "TagName", "value": "Value",
                  "quality": "Quality", "unit": "Units", "timezone": "UTC"},
        "tags": [{"name": "pressure", "unit": "bar", "minimum": 0, "maximum": 16},
                 {"name": "speed", "unit": "%", "minimum": 0, "maximum": 100}]}
    profile.update(extra)
    return profile


LONG = """Time,TagName,Value,Quality,Units
2026-10-01 08:00:00,pressure,8,192,bar
2026-10-01 08:00:00,speed,60,192,%
2026-10-01 08:00:01,pressure,8.1,192,bar
2026-10-01 08:00:01,speed,61,192,%
"""


def reasons_of(report):
    return report["summary"]["reason_counts"]


def test_clean_long_export_passes_and_freshness_is_reported_not_evaluated():
    report = audit_series(long_profile(), io.StringIO(LONG))
    assert report["summary"]["checks_passed"], report["summary"]
    assert report["summary"]["rows"] == 4
    checks = {item["check"] for item in report["not_evaluated"]}
    assert "freshness" in checks
    assert "quality" not in checks and "units" not in checks


@pytest.mark.parametrize("line,reason", [
    ("2026-10-01 08:00:02,pressure,8,192,kPa", "unit_mismatch"),
    ("2026-10-01 08:00:02,pressure,99,192,bar", "outside_engineering_range"),
    ("2026-10-01 08:00:02,pressure,I/O Timeout,192,bar", "nonfinite_or_nonnumeric_value"),
    ("2026-10-01 08:00:02,pressure,8,0,bar", "quality_bad"),
    ("2026-10-01 08:00:02,flow,8,192,m3/h", "unknown_tag"),
    ("2026-10-01 08:00:01,pressure,8,192,bar", "duplicate_timestamp"),
    ("2026-10-01 07:59:00,pressure,8,192,bar", "timestamp_went_backwards"),
    ("yesterday,pressure,8,192,bar", "invalid_timestamp")])
def test_long_export_row_faults_are_rejected(line, reason):
    report = audit_series(long_profile(), io.StringIO(LONG + line + "\n"))
    assert reasons_of(report).get(reason) == 1, reasons_of(report)
    assert not report["summary"]["checks_passed"]
    assert report["examples"][reason][0]["row"] == 5


def test_missing_quality_and_unit_columns_are_reported_not_evaluated():
    profile = long_profile()
    del profile["input"]["quality"], profile["input"]["unit"]
    data = "Time,TagName,Value\n2026-10-01 08:00:00,pressure,8\n2026-10-01 08:00:00,speed,60\n"
    report = audit_series(profile, io.StringIO(data))
    assert report["summary"]["checks_passed"]
    checks = {item["check"] for item in report["not_evaluated"]}
    assert {"quality", "units", "sample_groups", "gaps", "stuck_values"} <= checks


def test_quality_column_without_declared_encoding_is_not_guessed():
    profile = long_profile()
    del profile["quality_encoding"]
    report = audit_series(profile, io.StringIO(LONG.replace(",192,", ",0,")))
    assert "quality_bad" not in reasons_of(report)
    assert {"check": "quality", "reason": "quality column present but quality_encoding is not declared"} \
        in report["not_evaluated"]


def test_gap_limit_flags_long_silences_with_per_tag_override():
    profile = long_profile(max_gap_seconds=5)
    profile["tags"][1]["max_gap_seconds"] = 60
    data = LONG + "2026-10-01 08:00:30,pressure,8,192,bar\n2026-10-01 08:00:30,speed,60,192,%\n"
    report = audit_series(profile, io.StringIO(data))
    assert reasons_of(report) == {"gap_exceeds_limit": 1}
    assert report["examples"]["gap_exceeds_limit"][0]["tag"] == "pressure"
    assert report["examples"]["gap_exceeds_limit"][0]["gap_seconds"] == 29


def test_stuck_value_run_is_flagged_after_the_repeat_limit():
    profile = long_profile(max_repeats=3)
    rows = "".join(f"2026-10-01 08:00:{s:02d},pressure,8,192,bar\n" for s in range(6))
    report = audit_series(profile, io.StringIO("Time,TagName,Value,Quality,Units\n" + rows))
    assert reasons_of(report) == {"stuck_value": 2}


def test_synchronized_long_export_checks_sample_groups():
    profile = long_profile()
    profile["input"]["synchronized"] = True
    report = audit_series(profile, io.StringIO(LONG + "2026-10-01 08:00:02,pressure,8,192,bar\n"))
    assert report["summary"]["passed_rows"] == 5
    assert not report["summary"]["checks_passed"]
    assert report["group_examples"][0]["missing_tags"] == ["speed"]


WIDE = """t_stamp,Pump01/Pressure,Pump01/Speed
2026-10-01T08:00:00Z,8,60
2026-10-01T08:00:01Z,,61
2026-10-01T08:00:02Z,8.2,62
"""


def wide_profile():
    return {"schema": "tagaudit.profile.v1",
        "input": {"format": "wide", "timestamp": "t_stamp",
                  "columns": {"pressure": "Pump01/Pressure", "speed": "Pump01/Speed"}},
        "tags": [{"name": "pressure", "minimum": 0, "maximum": 16}, {"name": "speed", "minimum": 0, "maximum": 100}]}


def test_wide_export_blank_cell_is_a_missing_value_in_its_sample_group():
    report = audit_series(wide_profile(), io.StringIO(WIDE))
    summary = report["summary"]
    assert (summary["rows"], summary["rejected_rows"], summary["snapshots"], summary["passed_snapshots"]) == (5, 0, 3, 2)
    assert report["group_examples"][0]["missing_tags"] == ["pressure"]
    assert {"check": "units", "reason": "the export has no unit column"} in report["not_evaluated"]


MOSTLY_EMPTY = """Timestamp,A,B,C
2026-10-01T00:00:00Z,,1,1
2026-10-01T00:00:01Z,,,1
2026-10-01T00:00:02Z,,2,1
"""


def test_wide_export_counts_missing_values_per_tag():
    profile = {"schema": "tagaudit.profile.v1", "input": {"format": "wide", "timestamp": "Timestamp"},
               "tags": [{"name": "A"}, {"name": "B"}, {"name": "C"}]}
    report = audit_series(profile, io.StringIO(MOSTLY_EMPTY))
    assert report["summary"]["missing_by_tag"] == {"A": 3, "B": 1}


def test_synchronized_long_export_counts_missing_values_per_tag():
    profile = long_profile()
    profile["input"]["synchronized"] = True
    report = audit_series(profile, io.StringIO(LONG + "2026-10-01 08:00:02,pressure,8,192,bar\n"))
    assert report["summary"]["missing_by_tag"] == {"speed": 1}


def test_mapping_to_a_missing_column_fails_with_the_column_name():
    profile = wide_profile()
    profile["input"]["columns"]["speed"] = "Pump02/Speed"
    with pytest.raises(AuditError, match="Pump02/Speed"):
        audit_series(profile, io.StringIO(WIDE))


def test_naive_timestamps_without_timezone_say_offsets_were_not_checked():
    profile = long_profile()
    del profile["input"]["timezone"]
    report = audit_series(profile, io.StringIO(LONG))
    assert report["summary"]["checks_passed"]
    assert "daylight_saving_and_offsets" in {item["check"] for item in report["not_evaluated"]}
    assert report["time_span"]["first"] == "2026-10-01T08:00:00"  # wall clock, so no UTC "Z"
    assert report["time_span"]["basis"] == "local wall clock, no UTC offset declared"


@pytest.mark.parametrize("stamp,reason", [("2026-11-01 01:30:00", "ambiguous_local_time"),
    ("2026-03-08 02:30:00", "nonexistent_local_time")])
def test_daylight_saving_local_times_are_flagged_under_an_iana_zone(stamp, reason):
    profile = long_profile()
    profile["input"]["timezone"] = "America/New_York"
    report = audit_series(profile, io.StringIO(f"Time,TagName,Value,Quality,Units\n{stamp},pressure,8,192,bar\n"))
    assert reasons_of(report) == {reason: 1}


@pytest.mark.parametrize("fmt,first,second", [("epoch_ms", "1790841600000", "1790841601000"),
    ("epoch_s", "1790841600", "1790841601.5"), ("%d/%m/%Y %H:%M:%S", "01/10/2026 08:00:00", "01/10/2026 08:00:01")])
def test_epoch_and_pattern_timestamps_are_ordered(fmt, first, second):
    profile = long_profile()
    profile["input"]["timestamp_format"] = fmt
    data = f"Time,TagName,Value,Quality,Units\n{second},pressure,8,192,bar\n{first},pressure,8,192,bar\n"
    assert reasons_of(audit_series(profile, io.StringIO(data))) == {"timestamp_went_backwards": 1}


def test_examples_are_capped_but_counts_are_complete():
    rows = "".join(f"2026-10-01 08:{m:02d}:00,pressure,99,192,bar\n" for m in range(12))
    report = audit_series(long_profile(), io.StringIO("Time,TagName,Value,Quality,Units\n" + rows), examples=3)
    assert reasons_of(report) == {"outside_engineering_range": 12}
    assert len(report["examples"]["outside_engineering_range"]) == 3
    assert "rows" not in report


def test_full_detail_keeps_every_row():
    report = audit_series(long_profile(), io.StringIO(LONG), detail="full")
    assert len(report["rows"]) == 4


def test_row_limit_is_enforced():
    with pytest.raises(AuditError, match="row limit"):
        audit_series(long_profile(), io.StringIO(LONG), max_rows=3)


def test_empty_export_is_not_a_success():
    assert not audit_series(long_profile(), io.StringIO("Time,TagName,Value,Quality,Units\n"))["summary"]["checks_passed"]


@pytest.mark.parametrize("header,expected", [
    ("capture_id,asset_id,sequence,tag,value,unit,status_code,source_timestamp,server_timestamp,received_timestamp,unit_origin", "native"),
    ("Time,TagName,Value,Quality,Units", "long"), ("_time,_field,_value", "long"),
    ("t_stamp,Pump01/Pressure,Pump01/Speed", "wide"), ("Timestamp,FT-101,PT-201", "wide")])
def test_format_detection_from_headers(header, expected):
    assert detect_format(header.split(","))["format"] == expected


def test_format_detection_refuses_files_without_a_timestamp_column():
    with pytest.raises(AuditError, match="timestamp"):
        detect_format(["a", "b", "c"])


def test_split_date_and_time_columns_are_named_as_unsupported():
    with pytest.raises(AuditError, match="split date and time across several columns"):
        detect_format(["PackageID", "GPS_year_UTC", "GPS_month_UTC", "GPS_day_UTC", "presA_Pa"])
