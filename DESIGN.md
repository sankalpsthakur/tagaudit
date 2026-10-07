# Design notes for v0.1

## Purpose

Industrial teams pull tag data out of historians and OPC UA servers to train models, tune
controllers and write reports. Bad units, quality flags, duplicate timestamps, gaps, stuck
values and clock-change hours slip through and quietly corrupt the result. `tagaudit` is a
local check that runs before anyone trusts the data.

The first users are data and controls engineers who already have a CSV export and want an
answer in one command, without installing a platform.

## Origin

The core is the telemetry audit from the Forge Industrial Agent Lab Space (Apache-2.0, same
author), extracted into its own package. That version only read its own 11-column capture
format. v0.1 adds the formats people actually have, and fixes a Python 3.10 parsing bug that
rejected nearly every capture there.

## Scope of v0.1

- `tagaudit check FILE [--profile P]`: long and wide historian exports and native captures.
  Text report by default, JSON on request. Exit codes 0 / 2 / 1.
- `tagaudit init FILE`: a starter profile with the layout, tags and observed units.
- `tagaudit collect`: the bounded, read-only OPC UA collector, behind the `opcua` extra.
- Checks: units, ranges (optional, one-sided allowed), quality codes in three explicit
  encodings, numeric values, duplicate and backwards timestamps, gaps, stuck values,
  ambiguous and nonexistent local times, sample-group completeness. Native captures add the
  source/server/receive freshness checks.
- Every check the input can't support is reported under `not_evaluated`, never skipped silently.

## Decisions

| Decision | Why |
|---|---|
| Never fabricate missing fields (sequence, receive time, unit origin) for exports | Fake values would produce fake passes and fails. Freshness is reported as not evaluated instead. |
| `init` never guesses ranges, quality encoding or time zone | A range taken from the data passes by construction. OPC UA status 0 is good while OPC DA quality 0 is bad, so guessing can invert the result. |
| Separate code paths for native captures and exports | Native checks depend on three timestamps per value; mixing them would weaken both. Shared value checks have the same reason names. |
| Stream exports row by row | Real exports run to millions of rows. Measured on an Apple Silicon Mac with Python 3.14: 2,000,000 long-format rows (78 MB, 20 tags, all checks on) in 10.2 s with 26 MB peak memory. A real 57,000-row 3W well recording also peaked at 26 MB, so memory tracks the number of tags, not rows. |
| Reports keep counts for everything but only the first N examples per problem | Full row detail is available with `--full`. |
| Line numbers in examples are file lines (header = 1) | They match what you see in a text editor or spreadsheet. |
| Standard library only (`tzdata` on Windows) | Easy to install on locked-down engineering machines. `audit.py` also runs as a single file. |
| Keep `asyncua==2.0.1` pinned for the collector | The collector decodes Read responses itself and was tested against that release's wire helpers. |
| Accept the old `forge.telemetry.audit.v1` profile schema | Existing Forge kits and Space profiles keep working. |

## Tested on real data

- A Petrobras 3W well recording (57,000 rows, 29 columns, converted from parquet, not
  included here). Every timestamp parsed. The report shows the 23 sensor columns that are
  empty in every row, and the label columns missing for the first hour (3,600 rows). An
  earlier version buried this in repeated group lines, which led to the per-tag
  missing-values summary.
- An AirCore atmospheric sensor log that splits date and time across seven columns.
  `tagaudit` refuses it and names the reason, instead of guessing.

## Not in v0.1

- Date and time split across several columns.
- Semicolon-delimited files and decimal commas, and a second header row holding units.
- Vendor-specific export presets. None have been tested against a real export from that
  product, so the README doesn't claim support for any.
- Per-tag quality columns in wide exports, and tag aliases in long exports.
- Rate-of-change, spike and noise checks, and anything that needs a model of the process.
- Live monitoring, a server, or a UI. The Forge Space keeps its browser demo.

## Open questions

1. **PyPI.** Until a release exists, install from GitHub (see the README).
2. **Collector scope.** The OPC UA collector ships in v0.1 behind the `opcua` extra. If the
   pinned `asyncua` dependency becomes a maintenance burden, it can move to its own package.
3. **Forge Space.** The Space's telemetry audit page should point here.
