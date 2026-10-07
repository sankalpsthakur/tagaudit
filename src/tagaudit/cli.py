"""tagaudit check | init | collect

Exit codes: 0 all checks passed, 2 checks ran and found problems, 1 the input or
profile could not be read.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

from . import __version__
from .audit import CSV_FIELDS, MAX_BYTES, MAX_ROWS, QUALITY_ENCODINGS, AuditError, audit_csv
from .infer import infer_profile
from .report import finalize, render_text
from .series import DEFAULT_EXAMPLES, audit_series

NO_PROFILE_NOTE = ("No profile given: units were compared within the file only; ranges, quality, gaps and "
                   "stuck values were not checked. Write an editable profile with "
                   "`tagaudit init FILE -o profile.json`, then run `tagaudit check FILE --profile profile.json`.")


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(1, f"{self.prog}: error: {message}\n")


def _parser():
    parser = _Parser(prog="tagaudit", description="Check industrial tag data before you trust it.")
    parser.add_argument("--version", action="version", version=f"tagaudit {__version__}")
    commands = parser.add_subparsers(dest="command", required=True, parser_class=_Parser)

    check = commands.add_parser("check", help="audit a CSV export or capture")
    check.add_argument("file", type=Path, help="CSV file: historian export (long or wide) or native capture")
    check.add_argument("--profile", type=Path, help="profile JSON; without one, tagaudit infers a minimal one")
    check.add_argument("--output", "-o", type=Path, help="write the JSON report to this file")
    check.add_argument("--json", action="store_true", help="print the JSON report instead of text")
    check.add_argument("--full", action="store_true", help="keep every row in the JSON report")
    check.add_argument("--examples", type=int, default=DEFAULT_EXAMPLES, help="examples kept per problem")
    check.add_argument("--max-rows", type=int, help=f"stop after this many rows (native default {MAX_ROWS:,})")
    check.add_argument("--max-mb", type=int, default=MAX_BYTES // 2**20, help="native capture size limit in MB")

    init = commands.add_parser("init", help="write a starter profile from an export")
    init.add_argument("file", type=Path)
    init.add_argument("--output", "-o", type=Path, help="profile path (default: print to stdout)")
    init.add_argument("--asset-id")
    init.add_argument("--quality-encoding", choices=QUALITY_ENCODINGS)
    init.add_argument("--timezone", help="zone for timestamps without a UTC offset, e.g. UTC or Europe/Berlin")

    commands.add_parser("collect", help="read OPC UA values into a capture and audit it (needs tagaudit[opcua])",
                        add_help=False)
    return parser


def _open(path):
    return open(path, encoding="utf-8-sig", newline="")


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _profile(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise AuditError(f"profile is not valid JSON: {exc}") from exc


def _native_header(path):
    with _open(path) as stream:
        header = next(csv.reader(stream), [])
    return {name.strip() for name in header} == set(CSV_FIELDS)


def _check(args):
    notes = []
    if args.profile:
        profile = _profile(args.profile)
    else:
        with _open(args.file) as stream:
            profile, _ = infer_profile(stream)
        notes.append(NO_PROFILE_NOTE)
    detail = "full" if args.full else "examples"
    if isinstance(profile, dict) and "input" in profile:
        with _open(args.file) as stream:
            report = audit_series(profile, stream, examples=args.examples, detail=detail, max_rows=args.max_rows)
    else:
        if not _native_header(args.file):
            raise AuditError("this profile has no input section, so the file must be a native capture. "
                             "For a historian export, write a profile with `tagaudit init FILE -o profile.json`.")
        content = args.file.read_bytes().decode("utf-8-sig")
        report = audit_csv(profile, content, max_rows=args.max_rows or MAX_ROWS, max_bytes=args.max_mb * 2**20)
    report = finalize(report, examples=args.examples, full=args.full, source=args.file.name,
                      input_sha256=_sha256(args.file))
    if args.output:
        args.output.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, allow_nan=False) if args.json
          else render_text(report, notes=notes, output=args.output))
    return 0 if report["summary"]["checks_passed"] else 2


def _init(args):
    with _open(args.file) as stream:
        profile, notes = infer_profile(stream, asset_id=args.asset_id, quality_encoding=args.quality_encoding,
                                       timezone=args.timezone)
    text = json.dumps(profile, indent=2) + "\n"
    if args.output:
        args.output.write_text(text, encoding="utf-8")
        notes.append(f"Profile written to {args.output}.")
    else:
        sys.stdout.write(text)
    sys.stderr.write("\n".join(notes) + "\n")
    return 0


def _collect(argv):
    if importlib.util.find_spec("asyncua") is None:
        raise AuditError("the OPC UA collector needs the optional extra: pip install 'tagaudit[opcua]'")
    from . import opcua
    try:
        return opcua.main(argv, prog="tagaudit collect")
    except SystemExit as exc:
        # The collector's argparse exits 2 on usage errors; here 2 means "checks failed".
        return 1 if exc.code == 2 or not isinstance(exc.code, int) else exc.code


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    try:
        if argv[:1] == ["collect"]:
            return _collect(argv[1:])
        try:
            args = _parser().parse_args(argv)
        except SystemExit as exc:
            return exc.code if isinstance(exc.code, int) else 1
        return _check(args) if args.command == "check" else _init(args)
    except (AuditError, OSError, UnicodeError) as exc:
        print(f"tagaudit: error: {exc}", file=sys.stderr)
        return 1
