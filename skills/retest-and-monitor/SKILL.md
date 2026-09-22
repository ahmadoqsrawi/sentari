---
name: retest-and-monitor
description: Verify that security fixes hold and track a target over time with Sentari. Diffs a fresh assessment against a prior run (fixed, still present, new), schedules recurring retests, and reports trends and cross-asset correlation from stored runs. Use when the user wants to confirm remediation, retest after a fix, set up continuous or scheduled scanning, or see how findings change over time.
license: Proprietary
metadata:
  author: Ahmad
  homepage: https://github.com/ahmadoqsrawi/sentari
---

# Retesting and monitoring with Sentari

Always pass `--scope` and `--authorized`.

## Confirm a fix (diff against a baseline)

```bash
# baseline
sentari https://app.example.com --scope app.example.com --authorized --json baseline.json
# after the fix, diff against it
sentari https://app.example.com --scope app.example.com --authorized --retest baseline.json
```

The retest prints each finding as fixed, still present, or new. Exit reflects the delta so a fix can be gated in CI.

## Track over time with a database

```bash
sentari https://app.example.com --scope app.example.com --authorized --db sentari.db
sentari https://app.example.com --scope app.example.com --authorized --db sentari.db --retest-latest
```

`--db` accepts a SQLite file path or a `postgres://` URL. `--retest-latest` diffs against this target's most recent stored run.

## Trends and cross-asset correlation

Read-only views over stored runs (from `--db` or a `--runs-dir`):

```bash
sentari --trends --db sentari.db          # severity counts per run over time
sentari --correlate --db sentari.db       # a finding seen across more than one target
```

## Scheduled / continuous retests

With the distributed extra (`pip install ".[distributed]"`) and a broker, Celery beat reruns targets on a cron and reports the delta. Configure with `SENTARI_SCHEDULE_*` and dispatch scans with `--enqueue`. Start a worker: `celery -A sentari.tasks worker`.

## Ship deltas to a SIEM

```bash
sentari https://app.example.com --scope app.example.com --authorized \
  --siem-url https://splunk.example.com:8088 --siem-type splunk --siem-token "$TOKEN"
```
