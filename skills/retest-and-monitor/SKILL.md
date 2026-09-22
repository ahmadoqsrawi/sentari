---
name: retest-and-monitor
description: Verify that security fixes hold and track a target over time with Sentari. Diffs a fresh assessment against a prior run (fixed, still present, new), schedules recurring retests, and reports trends and cross-asset correlation from stored runs. Use when the user wants to confirm remediation, retest after a fix, set up continuous or scheduled scanning, or see how findings change over time.
license: AGPL-3.0-or-later
metadata:
  author: Ahmad
  homepage: https://github.com/ahmadoqsrawi/sentari
---

# Retesting and monitoring with Sentari

Confirm fixes landed and watch a target over time, all from the same evidence-backed runs. Install and the full flag set are in the **penetration-testing-with-sentari** skill.

## 1. Confirm authorization

The target is the user's or authorized. Always pass `--scope` and `--authorized`.

## 2. Capture a baseline

```bash
sentari https://app.example.com --scope app.example.com --authorized --json baseline.json
```

## 3. Confirm a fix (diff against the baseline)

```bash
sentari https://app.example.com --scope app.example.com --authorized --retest baseline.json
```

The retest labels each finding fixed, still present, or new. Re-testing is the only reliable confirmation a fix landed; do not trust a patch until the finding is gone.

## 4. Track over time with a database

```bash
sentari https://app.example.com --scope app.example.com --authorized --db sentari.db
sentari https://app.example.com --scope app.example.com --authorized --db sentari.db --retest-latest
```

`--db` accepts a SQLite file path or a `postgres://` URL. `--retest-latest` diffs against this target's most recent stored run.

## 5. Trends and cross-asset correlation

Read-only views over stored runs (from `--db` or a `--runs-dir`):

```bash
sentari --trends --db sentari.db          # severity counts per run over time
sentari --correlate --db sentari.db       # a finding seen across more than one target
```

## 6. Scheduled / continuous retests

With the distributed extra (`pip install ".[distributed]"`) and a broker, Celery beat reruns targets on a cron and reports the delta. Configure with `SENTARI_SCHEDULE_*`, dispatch scans with `--enqueue`, and start a worker with `celery -A sentari.tasks worker`.

## 7. Ship deltas onward

```bash
sentari https://app.example.com --scope app.example.com --authorized \
  --siem-url https://splunk.example.com:8088 --siem-type splunk --siem-token "$TOKEN"
```

For the dashboard and other export formats, see **security-reporting-and-dashboards**. To remediate what a retest still shows, see **fix-security-vulnerabilities-with-sentari**.
