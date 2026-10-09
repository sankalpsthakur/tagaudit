# Changelog

## 0.1.1 (unreleased)

- Publish workflow: the upload accepts an API-token secret as a fallback to trusted publishing. No code changes.

## 0.1.0 (2026-10-07)

First release as a standalone package, extracted from the Forge Industrial Agent Lab
telemetry audit.

- Reads long and wide historian CSV exports through a profile `input` section, as well as
  native OPC UA captures.
- `tagaudit check` without a profile infers the layout and reports what it couldn't check.
- `tagaudit init` writes a starter profile without guessing ranges, quality encoding or time zone.
- New checks for exports: duplicate and backwards timestamps, gaps (`max_gap_seconds`), stuck
  values (`max_repeats`), and local times that are ambiguous or nonexistent around clock changes.
- New `opc_da_quality` encoding, where 192 is good and 0 is bad.
- Tag ranges are optional and may be one-sided. Undeclared ranges are reported as not evaluated.
- Plain-language text report. The JSON report keeps counts plus the first examples of each
  problem, and `--full` keeps every row.
- Missing values are summarized per tag, naming the tags that are empty in every row.
- Fixed: on Python 3.10, timestamps whose fractional seconds weren't exactly 3 or 6 digits
  were rejected. Captures store 9 digits, so nearly every native capture failed there.
