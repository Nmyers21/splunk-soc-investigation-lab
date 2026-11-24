# Service Origin Anomaly
Status: authored, unvalidated in Splunk. No detection results are asserted.

Objective: Service origin novelty. The runnable SPL is [service_origin_anomaly.spl](service_origin_anomaly.spl); investigative command explanations are in [the corresponding query notes](../queries/09_service_accounts.md).

- MITRE ATT&CK: T1078.002 Domain Accounts (hypothesis).
- Suggested severity: Medium; adjust after impact and identity review.
- Threshold: At least 3 earlier account logons; first observed origin in lookback.
- Frequency / cron: `0 * * * *`; earliest `-7d`, latest `now`.
- Result: one or more candidate evidence rows, not a confirmed incident.
- Suppression grouping: `Account_Name, Workstation_Name`; start at 30 minutes, and review the risk of hiding ongoing activity.

False positives: Migrations, restore tests and short history. Tune using approved identity/origin inventories and change records, rather than blanket exemptions. Document excluded populations and test boundaries, late arrival, repeated successes and missing enrichment. Never tune against the instructor answer key.

Analyst response: inspect raw evidence, confirm identity and asset context, compare the earlier baseline, check authorized changes and correlate endpoint/network telemetry. Preserve timestamps and event IDs. Recommend proportionate containment only after triage; no automated blocking or account changes are performed here.

For service novelty the seven-day lookback is a teaching baseline, relearned each run; missing history and search-window shifts create false novelty. Use a curated, versioned baseline with explicit training/evaluation periods in a mature deployment.

See [scheduled alert setup](../docs/SCHEDULED_ALERTS.md). Remove only the final recent-candidate filter for historical manual testing; do not claim a zero-result live schedule validates this fixed historical dataset. Execution windows overlap for context; suppression and a durable last-seen event ID are needed to prevent duplicate tickets. Current schedules assume on-time data and can miss late arrivals; tune ingestion delay and test recovery windows.
