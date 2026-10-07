import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest
from tagaudit import __version__
from tagaudit.cli import main

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def run(capsys, *args):
    code = main([str(arg) for arg in args])
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_clean_native_capture_passes(capsys):
    code, out, _ = run(capsys, "check", EXAMPLES / "capture-good.csv", "--profile", EXAMPLES / "capture-profile.json")
    assert code == 0
    assert "PASS" in out


def test_faulty_native_capture_fails_with_plain_language_reasons(capsys):
    code, out, _ = run(capsys, "check", EXAMPLES / "capture-faults.csv", "--profile", EXAMPLES / "capture-profile.json")
    assert code == 2
    assert "FAIL" in out
    assert "unit_mismatch" in out and "unit differs from the profile" in out


def test_failing_sample_groups_name_their_actual_cause(capsys):
    _, out, _ = run(capsys, "check", EXAMPLES / "capture-faults.csv", "--profile", EXAMPLES / "capture-profile.json")
    assert "sequence 1  contains rejected values" in out
    assert "sequence 4  missing speed" in out
    assert "sequence 5  values received 0.8 s apart, over the skew limit" in out


def test_synchronized_long_groups_are_labelled_by_timestamp(capsys, tmp_path):
    profile = json.loads((EXAMPLES / "historian-profile.json").read_text())
    profile["input"]["synchronized"] = True
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(profile))
    _, out, _ = run(capsys, "check", EXAMPLES / "historian-long.csv", "--profile", path)
    assert "sequence None" not in out
    assert "  2026-10-25 01:59:44  repeated PT-101" in out
    assert "  2026-10-25 01:59:45  missing PT-101" in out


def test_text_report_summarises_missing_values_by_tag(capsys, tmp_path):
    rows = "".join(f"2026-10-01T00:00:{s:02d}Z,,{'' if s == 1 else s},1,2,3,4,5,6,7,8,9\n" for s in range(4))
    path = tmp_path / "wide.csv"
    path.write_text("Timestamp,EMPTY,B,T01,T02,T03,T04,T05,T06,T07,T08,T09\n" + rows)
    _, out, _ = run(capsys, "check", path)
    assert "Missing values (out of 4 sample groups)" in out
    assert "  always empty" in out and "EMPTY" in out
    assert "  B" in out and "1  (25.0%)" in out
    assert "and 4 more" in out  # long tag lists are shortened in text


def test_historian_export_without_profile_checks_structure_and_lists_what_it_skipped(capsys):
    code, out, _ = run(capsys, "check", EXAMPLES / "historian-long.csv")
    assert code == 2
    for reason in ("unit_mismatch", "nonfinite_or_nonnumeric_value", "duplicate_timestamp", "timestamp_went_backwards"):
        assert reason in out
    assert "Not checked" in out and "tagaudit init" in out
    assert "quality_bad" not in out


def test_historian_export_with_profile_finds_every_planted_fault(capsys, tmp_path):
    report = tmp_path / "report.json"
    code, _, _ = run(capsys, "check", EXAMPLES / "historian-long.csv", "--profile", EXAMPLES / "historian-profile.json",
                     "--output", report)
    assert code == 2
    assert json.loads(report.read_text())["summary"]["reason_counts"] == {
        "unit_mismatch": 1, "outside_engineering_range": 1, "nonfinite_or_nonnumeric_value": 1, "quality_bad": 1,
        "quality_uncertain": 1, "duplicate_timestamp": 1, "stuck_value": 1, "gap_exceeds_limit": 2,
        "ambiguous_local_time": 2, "timestamp_went_backwards": 1}


def test_json_flag_prints_the_report(capsys):
    code, out, _ = run(capsys, "check", EXAMPLES / "historian-wide.csv", "--json")
    summary = json.loads(out)["summary"]
    assert code == 2
    assert (summary["snapshots"], summary["passed_snapshots"]) == (4, 3)


def test_report_file_keeps_examples_and_drops_row_detail_unless_full(capsys, tmp_path):
    trimmed, full = tmp_path / "trimmed.json", tmp_path / "full.json"
    args = ["check", EXAMPLES / "capture-faults.csv", "--profile", EXAMPLES / "capture-profile.json"]
    run(capsys, *args, "--output", trimmed)
    run(capsys, *args, "--output", full, "--full")
    trimmed, full = json.loads(trimmed.read_text()), json.loads(full.read_text())
    assert "rows" not in trimmed and trimmed["examples"]["unit_mismatch"][0]["tag"] == "pressure"
    assert len(full["rows"]) == full["summary"]["rows"]
    assert len(trimmed["input_file_sha256"]) == 64


def test_init_writes_an_editable_profile_without_guessing(capsys, tmp_path):
    path = tmp_path / "profile.json"
    code, out, err = run(capsys, "init", EXAMPLES / "historian-long.csv", "--output", path)
    assert code == 0
    profile = json.loads(path.read_text())
    assert profile["tags"] == [{"name": "PT-101", "unit": "bar"}, {"name": "FT-102", "unit": "m3/h"}]
    assert profile["quality_encoding"] is None and profile["input"]["timezone"] is None
    assert "quality_encoding" in out + err and "timezone" in out + err
    assert run(capsys, "check", EXAMPLES / "historian-long.csv", "--profile", path)[0] == 2


def test_init_records_explicit_choices(capsys, tmp_path):
    path = tmp_path / "profile.json"
    run(capsys, "init", EXAMPLES / "historian-long.csv", "--output", path, "--quality-encoding", "opc_da_quality",
        "--timezone", "Europe/Berlin", "--asset-id", "pump-station-1")
    profile = json.loads(path.read_text())
    assert (profile["quality_encoding"], profile["input"]["timezone"], profile["asset_id"]) == (
        "opc_da_quality", "Europe/Berlin", "pump-station-1")


def test_init_for_wide_export_uses_columns_as_tags(capsys, tmp_path):
    path = tmp_path / "profile.json"
    assert run(capsys, "init", EXAMPLES / "historian-wide.csv", "--output", path)[0] == 0
    profile = json.loads(path.read_text())
    assert [tag["name"] for tag in profile["tags"]] == ["PT-101", "FT-102"]
    assert profile["input"]["format"] == "wide"


def test_init_refuses_native_captures(capsys):
    code, _, err = run(capsys, "init", EXAMPLES / "capture-good.csv")
    assert code == 1 and "profile" in err


def test_native_capture_without_profile_explains_what_to_pass(capsys):
    code, _, err = run(capsys, "check", EXAMPLES / "capture-good.csv")
    assert code == 1 and "--profile" in err


def test_historian_export_with_native_profile_points_to_init(capsys):
    code, _, err = run(capsys, "check", EXAMPLES / "historian-long.csv", "--profile", EXAMPLES / "capture-profile.json")
    assert code == 1 and "tagaudit init" in err


def test_row_limit_is_an_input_error(capsys):
    code, _, err = run(capsys, "check", EXAMPLES / "historian-long.csv", "--max-rows", "5")
    assert code == 1 and "row limit" in err


def test_missing_file_is_an_input_error(capsys, tmp_path):
    assert run(capsys, "check", tmp_path / "absent.csv")[0] == 1


@pytest.mark.skipif(importlib.util.find_spec("asyncua") is not None, reason="asyncua is installed")
def test_collect_without_the_opcua_extra_says_how_to_install(capsys, tmp_path):
    code, _, err = run(capsys, "collect", "--profile", EXAMPLES / "capture-profile.json", "--endpoint",
                       "opc.tcp://127.0.0.1:4840", "--csv", tmp_path / "c.csv", "--output", tmp_path / "r.json")
    assert code == 1 and "tagaudit[opcua]" in err


@pytest.mark.skipif(importlib.util.find_spec("asyncua") is None, reason="needs the opcua extra")
def test_collect_usage_error_exits_1_not_the_failed_checks_code(capsys):
    code, _, err = run(capsys, "collect")
    assert code == 1 and "--profile" in err


@pytest.mark.skipif(importlib.util.find_spec("asyncua") is None, reason="needs the opcua extra")
def test_collect_help_names_the_subcommand(capsys):
    code, out, _ = run(capsys, "collect", "--help")
    assert code == 0 and out.startswith("usage: tagaudit collect")


def test_module_entry_point_reports_version():
    result = subprocess.run([sys.executable, "-m", "tagaudit", "--version"], capture_output=True, text=True)
    assert result.returncode == 0
    assert result.stdout.strip() == f"tagaudit {__version__}"
