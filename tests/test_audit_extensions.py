import pytest
from tagaudit.audit import CSV_FIELDS, AuditError, audit_csv, audit_rows, status_checks, validate_profile


@pytest.fixture
def profile():
    return {"schema": "tagaudit.profile.v1", "asset_id": "demo-pump", "freshness_basis": "server",
        "quality_encoding": "opcua_status_code", "max_age_seconds": 2, "max_future_seconds": 0.25,
        "max_snapshot_skew_seconds": 0.5, "tags": [{"name": "pressure", "unit": "bar", "minimum": 0, "maximum": 16}]}


@pytest.fixture
def row():
    return dict(zip(CSV_FIELDS, ["capture-01", "demo-pump", "1", "pressure", "8", "bar", "0x00000000",
        "2026-10-01T00:00:00Z", "2026-10-01T00:59:59.500Z", "2026-10-01T01:00:00Z", "server_property"], strict=True))


@pytest.mark.parametrize("schema", ["tagaudit.profile.v1", "forge.telemetry.audit.v1"])
def test_current_and_legacy_profile_schemas_are_accepted(profile, schema):
    assert validate_profile({**profile, "schema": schema})["asset_id"] == "demo-pump"


def test_unknown_profile_schema_is_rejected(profile):
    with pytest.raises(AuditError):
        validate_profile({**profile, "schema": "other.v1"})


@pytest.mark.parametrize("code,reasons", [
    ("192", []), ("0xC0", []), ("216", []),
    ("64", ["quality_uncertain"]), ("84", ["quality_uncertain"]),
    ("0", ["quality_bad"]), ("24", ["quality_bad"]),
    ("128", ["invalid_quality"]), ("65536", ["invalid_quality"]), ("good", ["invalid_quality"])])
def test_opc_da_quality_reads_the_quality_bits_where_192_is_good(code, reasons):
    assert status_checks(code, "opc_da_quality")[0] == reasons


@pytest.mark.parametrize("code,warning", [("216", "local_override"), ("193", "limit_low"),
    ("194", "limit_high"), ("195", "limit_constant")])
def test_opc_da_substatus_and_limit_bits_are_kept_as_warnings(code, warning):
    reasons, warnings, _ = status_checks(code, "opc_da_quality")
    assert reasons == []
    assert warning in warnings


def test_da_zero_is_bad_although_opcua_zero_is_good(profile, row):
    row["status_code"] = "0"
    assert audit_rows(profile, [row])["summary"]["checks_passed"]
    da = audit_rows({**profile, "quality_encoding": "opc_da_quality"}, [row])
    assert "quality_bad" in da["rows"][0]["reasons"]


def test_tag_without_limits_skips_range_check_and_reports_it(profile, row):
    profile["tags"][0] = {"name": "pressure", "unit": "bar"}
    row["value"] = "1000000"
    report = audit_rows(profile, [row])
    assert report["summary"]["checks_passed"]
    assert {"check": "engineering_range", "tags": ["pressure"],
            "reason": "no minimum or maximum declared"} in report["not_evaluated"]


@pytest.mark.parametrize("limits,value,rejected", [({"minimum": 0}, "-1", True), ({"minimum": 0}, "1e9", False),
    ({"maximum": 16}, "17", True), ({"minimum": None, "maximum": None}, "1e9", False)])
def test_one_sided_and_null_limits(profile, row, limits, value, rejected):
    profile["tags"][0] = {"name": "pressure", "unit": "bar", **limits}
    row["value"] = value
    reasons = audit_rows(profile, [row])["rows"][0]["reasons"]
    assert ("outside_engineering_range" in reasons) is rejected


def test_fully_declared_profile_reports_nothing_unevaluated(profile, row):
    assert audit_rows(profile, [row])["not_evaluated"] == []


def test_native_row_limit_is_adjustable(profile, row):
    second = {**row, "sequence": "2"}
    content = ",".join(CSV_FIELDS) + "\n" + "".join(",".join(r[f] for f in CSV_FIELDS) + "\n" for r in (row, second))
    with pytest.raises(AuditError, match="row limit"):
        audit_csv(profile, content, max_rows=1)
    assert audit_csv(profile, content, max_rows=2)["summary"]["rows"] == 2
