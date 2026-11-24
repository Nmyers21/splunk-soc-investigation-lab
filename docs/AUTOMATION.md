# Python automation
Requires Python 3.9+ and only the standard library. Run from the project root.

## Safe learning sequence
Start with the unrelated demonstration fixture:

```sh
python3 scripts/analyze_auth.py data/example_events.json --output-dir reports/practice
python3 -m unittest discover -s tests -v
```

The fixture is independent of the blind lab. The first command creates a JSON investigation summary, a CSV of candidate findings and a CSV of failure counts. Output folders are ignored by Git. Nothing is sent to an external service.

Only after your manual investigation, optionally run:

```sh
python3 scripts/analyze_auth.py soc_authentication_logs.csv --output-dir reports/local_analysis
```

That command will produce potential incident leads and may spoil your investigation. It has **not** been run on your dataset during implementation.

Input is a CSV with headers or a JSON array of objects containing all thirteen original fields. Validation requires supported event/status semantics, a failure reason only for 4625, an offset-bearing timestamp, valid IPs, nonempty context and unique positive lab EventRecordIDs. This validator expects the teaching schema and is not a universal raw-Windows parser. Unknown extra fields are dropped; invalid records cause the whole input to fail, rather than creating a misleading partial report.

`--failure-threshold`, `--spray-threshold`, and `--success-threshold` customize positive count thresholds. Defaults are 10 failures in ten minutes, ten distinct targeted accounts in thirty minutes, and five preceding failures in fifteen minutes before a success. Correlation keys include account, source and destination. Geographic detection remains an SPL investigation exercise; the Python script intentionally does not implement every query.

Dictionaries hold identity/source counts and per-key history. Deques retain bounded-time failure history; lists hold candidates. Repeated threshold-crossing events generate multiple candidate rows, deduplicated only by rule and triggering event ID. These rows are not incident counts. Service novelty compares against prior events in the selected input, requires three prior logons, and uses the `svc_` lab naming convention. Privileged context uses the timestamp's own clock offset, suitable for this single-offset dataset.

Limitations: sampled input, no session IDs, no trusted allowlist, no persistent baseline, no multi-run ticket deduplication, all events initially loaded into memory and historical keys retained until process exit. This is a small-file teaching tool, not a production streaming detector. API rows must match this schema before analysis. No account disablement, firewall modification, vulnerability scan or remediation occurs.

See [the line-by-line walkthrough](PYTHON_WALKTHROUGH.md) and [REST integration](REST_API.md). Tests use unrelated fixtures and mocked responses; they validate Python behavior, not SPL syntax or Splunk runtime behavior.
