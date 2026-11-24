# Brute Force
Status: authored, unvalidated in Splunk. No detection results are asserted.

Objective: Brute-force candidate. The runnable SPL is [brute_force.spl](brute_force.spl); investigative command explanations are in [the corresponding query notes](../queries/06_brute_force.md).

- MITRE ATT&CK: T1110.001 Password Guessing.
- Suggested severity: Medium; adjust after impact and identity review.
- Threshold: 10 failures / 10 minutes.
- Frequency / cron: `*/5 * * * *`; earliest `-15m@m`, latest `now`.
- Result: one or more candidate evidence rows, not a confirmed incident.
- Suppression grouping: `Account_Name, Source_Network_Address, ComputerName`; start at 30 minutes, and review the risk of hiding ongoing activity.

False positives: Stale credentials, client loops and user recovery. Tune using approved identity/origin inventories and change records, rather than blanket exemptions. Document excluded populations and test boundaries, late arrival, repeated successes and missing enrichment. Never tune against the instructor answer key.

Analyst response: inspect raw evidence, confirm identity and asset context, compare the earlier baseline, check authorized changes and correlate endpoint/network telemetry. Preserve timestamps and event IDs. Recommend proportionate containment only after triage; no automated blocking or account changes are performed here.

For service novelty the seven-day lookback is a teaching baseline, relearned each run; missing history and search-window shifts create false novelty. Use a curated, versioned baseline with explicit training/evaluation periods in a mature deployment.

See [scheduled alert setup](../docs/SCHEDULED_ALERTS.md). Remove only the final recent-candidate filter for historical manual testing; do not claim a zero-result live schedule validates this fixed historical dataset. Execution windows overlap for context; suppression and a durable last-seen event ID are needed to prevent duplicate tickets. Current schedules assume on-time data and can miss late arrivals; tune ingestion delay and test recovery windows.
