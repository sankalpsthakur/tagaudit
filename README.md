# tagaudit

[![CI](https://github.com/sankalpsthakur/tagaudit/actions/workflows/ci.yml/badge.svg)](https://github.com/sankalpsthakur/tagaudit/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/tagaudit)](https://pypi.org/project/tagaudit/)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue)](https://pypi.org/project/tagaudit/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/sankalpsthakur/tagaudit/blob/main/LICENSE)

Check industrial tag data before you trust it.

`tagaudit` reads a historian CSV export or an OPC UA capture and tells you which values to
distrust and why:

- wrong units and values outside the declared range
- bad or uncertain quality codes
- text where a number should be (`I/O Timeout`, `Bad Input`)
- duplicate and backwards timestamps
- gaps and stuck values
- local times that happen twice, or never, when the clocks change

It runs on your machine, needs only Python 3.10+, and never writes to a PLC or server.

## Quick start

```bash
pip install tagaudit
tagaudit check export.csv
```

Without a profile, `tagaudit` works out the layout and checks what the file alone can prove.
To check ranges, quality codes, gaps and stuck values, write a profile and edit it:

```bash
tagaudit init export.csv -o profile.json      # lists tags and units; you add limits
tagaudit check export.csv --profile profile.json
```

Output for [`examples/historian-long.csv`](https://github.com/sankalpsthakur/tagaudit/blob/main/examples/historian-long.csv) with
[`examples/historian-profile.json`](https://github.com/sankalpsthakur/tagaudit/blob/main/examples/historian-profile.json):

```text
tagaudit 0.1.0 · historian-long.csv · long export · asset pump-station-1
2026-10-24T23:59:40Z to 2026-10-24T23:59:58Z (UTC)

FAIL  10 of 20 values rejected

Problems
  ambiguous_local_time                  2  local time happens twice (clocks went back)
      line 19  PT-101 = 8.07  at 2026-10-25 02:00:01
      line 20  FT-102 = 42.0  at 2026-10-25 02:00:01
  gap_exceeds_limit                     2  gap since the previous value exceeds max_gap_seconds
      line 17  PT-101 = 8.06  at 2026-10-25 01:59:58
      line 18  FT-102 = 41.9  at 2026-10-25 01:59:58
  duplicate_timestamp                   1  same tag twice at the same time
      line 12  PT-101 = 8.04  at 2026-10-25 01:59:44
  nonfinite_or_nonnumeric_value         1  value is not a number
      line 9  FT-102 = I/O Timeout  at 2026-10-25 01:59:43
  outside_engineering_range             1  value outside the declared range
      line 6  PT-101 = 803  at 2026-10-25 01:59:42
  quality_bad                           1  quality code says bad
      line 9  FT-102 = I/O Timeout  at 2026-10-25 01:59:43
  quality_uncertain                     1  quality code says uncertain
      line 11  FT-102 = 41.8  at 2026-10-25 01:59:44
  stuck_value                           1  value unchanged for more than max_repeats samples
      line 16  FT-102 = 41.8  at 2026-10-25 01:59:48
  timestamp_went_backwards              1  earlier than this tag's previous value
      line 21  PT-101 = 8.06  at 2026-10-25 01:59:50
  unit_mismatch                         1  unit differs from the profile
      line 6  PT-101 = 803  at 2026-10-25 01:59:42

Not checked
  freshness                    exports carry no receive time, so data age at the edge is unknown
  sample_groups                long export is not declared synchronized
```

Exit codes: `0` all checks passed, `2` problems found, `1` the file or profile couldn't be
read. Add `--output report.json` for a JSON report, or `--json` to print it.

## What it reads

| Layout | Looks like | Notes |
|---|---|---|
| Long | `Timestamp,TagName,Value,Quality,Units` | One value per row. Quality and unit columns are optional. |
| Wide | `Timestamp,PT-101,FT-102` | One column per tag. A blank cell counts as a missing value in that row. |
| Native capture | written by `tagaudit collect` | Adds OPC UA source, server and receive timestamps, so freshness can be checked. |

For wide and synchronized long exports, the report also counts missing values per tag and
names the tags that are empty in every row.

Each file needs one column holding the full date and time. Exports that split date and time
across several columns aren't supported yet. Timestamps can be ISO 8601 with or without a UTC
offset, epoch seconds or milliseconds, or any `strptime` pattern. If they have no offset, set `input.timezone` (`UTC`, `+04:00` or a zone
such as `Europe/Berlin`). With a named zone, `tagaudit` flags times that occur twice or never
during clock changes.

## Profiles

A profile says what the data should look like. `tagaudit init` writes the layout, tags and
units it finds. It leaves the rest for you, because guessing them would make those checks
meaningless.

```json
{
  "schema": "tagaudit.profile.v1",
  "quality_encoding": "opc_da_quality",
  "max_gap_seconds": 5,
  "max_repeats": 3,
  "input": {"format": "long", "timestamp": "Timestamp", "tag": "TagName", "value": "Value",
            "quality": "Quality", "unit": "Units", "timezone": "Europe/Berlin"},
  "tags": [
    {"name": "PT-101", "unit": "bar", "minimum": 0, "maximum": 16},
    {"name": "FT-102", "unit": "m3/h", "minimum": 0, "maximum": 120, "max_gap_seconds": 10}
  ]
}
```

- `quality_encoding`: `opcua_status_code` (0 is good), `opc_da_quality` (192 is good, 0 is
  bad) or `quality_words` (`good`, `uncertain`, `bad`). The two numeric schemes read 0 in
  opposite ways, so `tagaudit` never guesses.
- `minimum` and `maximum`: either or both. Tags without them are listed under "Not checked".
- `max_gap_seconds`: the longest silence allowed between values of a tag.
- `max_repeats`: how many times in a row a value may repeat before it counts as stuck.
  Per-tag values override the profile-wide ones.
- Wide exports map tag names to columns with `"input": {"format": "wide", "columns": {"PT-101": "Pump01/Pressure"}}`.

## OPC UA captures

```bash
pip install "tagaudit[opcua]"
tagaudit collect --profile capture-profile.json --endpoint opc.tcp://192.168.0.10:4840 \
  --certificate client.pem --private-key client-key.pem --server-certificate server.der \
  --csv capture.csv --output capture.audit.json
```

The collector only reads: it exposes no Write or Call service, and it takes a bounded number
of samples (`--samples`, default 5). It records each value's source, server and receive
timestamps, so the audit can tell a fresh server timestamp on an old value from genuinely new
data. Use a server-side read-only role as well, because client code is not access control.
[`examples/capture-faults.csv`](https://github.com/sankalpsthakur/tagaudit/blob/main/examples/capture-faults.csv) shows the checks on a capture.

For machines without `pip`, copy `audit.py` out of the repository or the wheel. It runs on
its own with the standard library and checks native captures:
`python audit.py --profile profile.json --csv capture.csv --output report.json`.

## What a pass does not mean

A pass means the file matches its profile. It doesn't show that sensors are calibrated, that
the source was authentic, that an export is still current, or that a model trained on the data
will behave. Checks the file can't support are listed under "Not checked" instead of being
skipped silently.

## License

Apache-2.0. Copyright 2026 Sankalp Thakur.
