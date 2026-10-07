import csv
import io
import json
import subprocess
import sys
from pathlib import Path

import pytest
from tagaudit.audit import AuditError, CSV_FIELDS, audit_csv, audit_rows, validate_profile


@pytest.fixture
def profile():
    return {"schema":"forge.telemetry.audit.v1", "asset_id":"demo-pump", "freshness_basis":"server",
        "quality_encoding":"opcua_status_code", "max_age_seconds":2, "max_future_seconds":0.25,
        "max_snapshot_skew_seconds":0.5, "tags":[{"name":"pressure", "unit":"bar", "minimum":0, "maximum":16}]}


@pytest.fixture
def row():
    return dict(zip(CSV_FIELDS, ["capture-01","demo-pump","1","pressure","8","bar","0x00000000",
        "2026-10-01T00:00:00Z","2026-10-01T00:59:59.500Z","2026-10-01T01:00:00Z","server_property"], strict=True))


def test_unchanged_source_with_recent_server_check_passes_without_hiding_source_age(profile, row):
    report = audit_rows(profile, [row])
    assert report["summary"]["checks_passed"]
    assert report["rows"][0]["source_age_seconds"] == 3600
    assert "source_unchanged_or_old_check_server_provenance" in report["rows"][0]["warnings"]


def test_source_update_contract_remains_strict_when_explicitly_selected(profile, row):
    profile["freshness_basis"] = "source"
    report = audit_rows(profile, [row])
    assert not report["summary"]["checks_passed"]
    assert "stale_source_timestamp" in report["rows"][0]["reasons"]


@pytest.mark.parametrize("code,reason", [("0x40000000","quality_uncertain"),("0x80000000","quality_bad"),
    ("0xc0000000","quality_bad"),("0x00004000","metadata_changed_requires_review"),
    ("0x00008000","metadata_changed_requires_review"),("0x00000480","queue_overflow"),
    ("0x10000000","reserved_status_bits"),("nan","invalid_status_code")])
def test_quality_and_metadata_flags_reject(profile, row, code, reason):
    row["status_code"] = code
    result = audit_rows(profile, [row])
    assert reason in result["rows"][0]["reasons"]
    assert not result["summary"]["checks_passed"]


@pytest.mark.parametrize("field,value,reason", [
    ("value","nan","nonfinite_or_nonnumeric_value"),("value","Infinity","nonfinite_or_nonnumeric_value"),
    ("value",True,"nonfinite_or_nonnumeric_value"),("value","19","outside_engineering_range"),
    ("unit","kPa","unit_mismatch"),("tag","other","unknown_tag"),
    ("asset_id","other","asset_mismatch"),("unit_origin","profile_declaration","unit_provenance_missing"),
    ("server_timestamp","2026-10-01T00:59:00Z","stale_server_timestamp"),
    ("source_timestamp","2026-10-01T01:00:02Z","source_timestamp_in_future"),
    ("server_timestamp","2026-10-01T01:00:02Z","server_timestamp_in_future"),
    ("received_timestamp","2026-10-01T01:00:00","invalid_received_timestamp"),
    ("sequence","1.5","malformed_record_identity")])
def test_invalid_values_and_identity_reject(profile, row, field, value, reason):
    row[field] = value
    result = audit_rows(profile, [row])
    assert reason in result["rows"][0]["reasons"]
    assert not result["summary"]["checks_passed"]


def test_missing_required_channel_prevents_complete_snapshot(profile, row):
    profile["tags"].append({"name":"speed","unit":"%","minimum":0,"maximum":100})
    report = audit_rows(profile, [row])
    assert report["summary"]["passed_rows"] == 1
    assert not report["summary"]["checks_passed"]
    assert report["snapshots"][0]["missing_tags"] == ["speed"]


def test_sequence_and_receiver_time_regression_are_visible(profile, row):
    second = {**row, "sequence":"0", "received_timestamp":"2026-10-01T00:59:59.900Z"}
    report = audit_rows(profile, [row,second])
    assert "duplicate_or_reordered_sequence" in report["rows"][1]["reasons"]
    assert "receiver_time_went_backwards" in report["rows"][1]["reasons"]


def test_capture_restart_scopes_sequence_but_retains_quality_checks(profile, row):
    second = {**row, "capture_id":"capture-02", "sequence":"0"}
    report = audit_rows(profile, [row,second])
    assert report["summary"]["checks_passed"]
    assert report["summary"]["snapshots"] == 2


def test_snapshot_acquisition_skew_rejects_complete_but_incoherent_group(profile, row):
    profile["tags"].append({"name":"speed","unit":"%","minimum":0,"maximum":100})
    speed = {**row,"tag":"speed","value":"60","unit":"%","received_timestamp":"2026-10-01T01:00:01Z"}
    report = audit_rows(profile,[row,speed])
    assert report["summary"]["passed_rows"] == 2
    assert not report["summary"]["checks_passed"]
    assert report["snapshots"][0]["received_skew_seconds"] == 1


def test_unit_and_profile_changes_change_receipt_hash(profile, row):
    one = audit_rows(profile,[row])
    two = audit_rows({**profile,"max_age_seconds":3},[row])
    assert one["profile_sha256"] != two["profile_sha256"]


def test_coarse_quality_encoding_records_lost_status_detail(profile, row):
    profile["quality_encoding"] = "quality_words"
    row["status_code"] = "GOOD"
    report = audit_rows(profile,[row])
    assert report["summary"]["checks_passed"]
    assert "status_detail_unavailable" in report["rows"][0]["warnings"]


def test_empty_data_is_not_a_success(profile):
    assert not audit_rows(profile,[])["summary"]["checks_passed"]


def test_malformed_or_duplicate_csv_header_fails(profile):
    with pytest.raises(AuditError):
        audit_csv(profile,"tag,tag,value\npressure,pressure,8\n")


def test_non_object_rows_fail_and_normalized_tags_form_complete_groups(profile, row):
    with pytest.raises(AuditError):
        audit_rows(profile, [None])
    assert audit_rows(profile, [{**row, "tag": " pressure "}])["summary"]["checks_passed"]


@pytest.mark.parametrize("change", [{"freshness_basis":"guess"},{"max_age_seconds":float('nan')},
    {"max_age_seconds":True},{"max_snapshot_skew_seconds":-1},{"typo_limit":2}])
def test_bad_profiles_fail(profile, change):
    with pytest.raises(AuditError):
        validate_profile({**profile,**change})


def test_standalone_stdlib_cli_roundtrip_without_package_import(profile,row,tmp_path):
    output = io.StringIO()
    writer = csv.DictWriter(output,fieldnames=CSV_FIELDS)
    writer.writeheader(); writer.writerow(row)
    (tmp_path/'profile.json').write_text(json.dumps(profile))
    (tmp_path/'input.csv').write_text(output.getvalue())
    source=Path(__file__).resolve().parents[1]/'src/tagaudit/audit.py'
    result=subprocess.run([sys.executable,'-S',str(source),'--profile',str(tmp_path/'profile.json'),
        '--csv',str(tmp_path/'input.csv'),'--output',str(tmp_path/'audit.json')],capture_output=True,text=True)
    assert result.returncode == 0, result.stderr
    report=json.loads((tmp_path/'audit.json').read_text())
    assert report['summary']['checks_passed']
    assert len(report['csv_sha256']) == 64


def test_one_nanosecond_future_timestamp_cannot_pass_zero_allowance(profile, row):
    profile['max_future_seconds'] = 0
    row.update(source_timestamp='2026-10-01T01:00:00.000000001Z',
        server_timestamp='2026-10-01T01:00:00Z')
    result = audit_rows(profile, [row])
    assert 'source_timestamp_in_future' in result['rows'][0]['reasons']
    assert not result['summary']['checks_passed']


def test_submicrosecond_age_limit_is_compared_without_truncation(profile, row):
    profile['max_age_seconds'] = 1e-7
    row.update(source_timestamp='2026-10-01T01:00:00.000000100Z',
        server_timestamp='2026-10-01T01:00:00.000000100Z',
        received_timestamp='2026-10-01T01:00:00.000000201Z')
    result = audit_rows(profile, [row])
    assert 'stale_server_timestamp' in result['rows'][0]['reasons']
    assert result['rows'][0]['server_age_nanoseconds'] == 101


def test_submicrosecond_acquisition_skew_cannot_pass(profile, row):
    profile['max_snapshot_skew_seconds'] = 1e-7
    profile['tags'].append({'name':'speed','unit':'%','minimum':0,'maximum':100})
    row.update(source_timestamp='2026-10-01T01:00:00Z',
        server_timestamp='2026-10-01T01:00:00Z',
        received_timestamp='2026-10-01T01:00:00.000000100Z')
    second = {**row,'tag':'speed','unit':'%','value':'60',
        'received_timestamp':'2026-10-01T01:00:00.000000201Z'}
    result = audit_rows(profile, [row,second])
    assert result['summary']['passed_rows'] == 2
    assert not result['summary']['checks_passed']
    assert result['snapshots'][0]['received_skew_nanoseconds'] == 101


def test_submicrosecond_receiver_regression_is_visible(profile, row):
    row.update(source_timestamp='2026-10-01T01:00:00Z',
        server_timestamp='2026-10-01T01:00:00Z',
        received_timestamp='2026-10-01T01:00:00.000000201Z')
    second = {**row,'sequence':'2','received_timestamp':'2026-10-01T01:00:00.000000100Z'}
    result = audit_rows(profile, [row,second])
    assert 'receiver_time_went_backwards' in result['rows'][1]['reasons']


def test_offset_equivalence_retains_nine_digit_receiver_time(profile, row):
    row.update(source_timestamp='2026-10-01T05:00:00.100000001+04:00',
        server_timestamp='2026-10-01T01:00:00.100000001Z',
        received_timestamp='2026-10-01T01:00:00.100000001Z')
    result = audit_rows(profile, [row])
    assert result['summary']['checks_passed']
    assert result['rows'][0]['source_age_nanoseconds'] == 0
    assert result['rows'][0]['received_timestamp'] == '2026-10-01T01:00:00.100000001+00:00'


def test_nanosecond_allowance_boundary_and_second_rollover(profile, row):
    profile.update(max_age_seconds=1e-9,max_future_seconds=1e-9)
    row.update(source_timestamp='2026-10-01T00:59:59.999999999Z',
        server_timestamp='2026-10-01T01:00:00.000000001Z',
        received_timestamp='2026-10-01T01:00:00Z')
    result = audit_rows(profile, [row])
    assert result['summary']['checks_passed']
    assert result['rows'][0]['source_age_nanoseconds'] == 1
    assert result['rows'][0]['server_age_nanoseconds'] == -1
    row['server_timestamp'] = '2026-10-01T01:00:00.000000002Z'
    assert 'server_timestamp_in_future' in audit_rows(profile,[row])['rows'][0]['reasons']


def test_out_of_range_utc_normalization_is_an_invalid_record(profile, row):
    row['received_timestamp'] = '0001-01-01T00:00:00+01:00'
    result = audit_rows(profile,[row])
    assert 'invalid_received_timestamp' in result['rows'][0]['reasons']
    assert not result['summary']['checks_passed']
