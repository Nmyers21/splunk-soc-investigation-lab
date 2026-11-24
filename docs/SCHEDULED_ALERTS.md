# Scheduled alerts
These rules are authored and locally inspected only. Execute and validate them yourself in Splunk before describing them as tested.

1. Confirm ingestion and extracted fields using docs/SPLUNK_SETUP.md. Set user timezone to America/Chicago for this lab's calendar display.
2. Open a detection SPL file. For historical testing, remove its final `_time>=relative_time(now(),...)` line, choose the fixed seven-day period (or All time), execute it and record the query version, time range, result count, screenshots and false-positive review. Do not paste findings into public docs until you choose to publish them.
3. For a live or explicitly replayed stream, restore that line and use the rule's documented earliest/latest range. A fixed November dataset will not produce new results forever. Do not alter the original dataset to replay it; use a separate copy and index if needed.
4. In Search & Reporting choose Save As → Alert, give a descriptive name, select Scheduled, enter the documented cron expression and time bounds. Trigger when the number of results is greater than zero. Start with the triggered-alerts action only; sending email/webhooks requires separate configuration and authorization.
5. Configure per-result throttling/suppression with the rule's grouping fields. Confirm your Splunk version's alert behavior, search owner permissions, schedule timezone and license capabilities. Free editions may restrict alerting; manual searches still teach the logic.
6. Confirm scheduler execution, inspect raw rows and record evidence. Overlapping context windows can repeat rows; a real ticket integration needs persistent deduplication keyed by rule and evidence record ID.

Rules use event time, not ingestion time. Document delays, bucket/rolling limits, clock drift and how a schedule resumes after downtime. Suppression reduces noise but can conceal updates; evaluate the tradeoff.

[Splunk alerting documentation](https://help.splunk.com/en/splunk-enterprise/alert-and-respond/alerting-manual).
