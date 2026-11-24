# Interview preparation

Use the concepts below to explain your reasoning in your own words. These are study notes, not claims of completed work.

## Ten Splunk questions

1. **What is a source type?** A parsing and field-extraction classification. A wrong source type can corrupt timestamps or omit fields.

2. **What is the difference between index and source type?** Index selects stored data; source type describes its format. Search both deliberately.

3. **How do you verify ingestion?** Check count, unique record IDs, timestamp range and required fields; compare with the original file.

4. **When do you use stats?** Aggregate records by a grouping key. Aggregation removes ungrouped raw fields unless explicitly retained.

5. **What does streamstats add?** Ordered running/windowed context on each row. Sorting and window limits affect correctness.

6. **Why use EventCode rather than Status alone?** Event IDs distinguish authentication, logoff, explicit credentials and privilege-session events.

7. **What is wrong with All time in a production alert?** Unbounded cost and stale repeated findings. Use a defined lookback and recent candidate horizon.

8. **How do you distinguish host from ComputerName?** Splunk metadata host can identify the input; ComputerName is the normalized emitting system in this dataset.

9. **What does dc measure?** Distinct values, useful for breadth across identities or sources rather than just volume.

10. **How do you investigate a zero-result search?** Check time range, index, source type, event parsing, permissions, filters and thresholds before concluding no suspicious activity.

## Ten incident response questions

1. **How do you triage a suspicious logon?** Validate evidence, identity, asset, time and expected behavior, then corroborate and assess impact.

2. **How do you distinguish password spraying and brute force?** Spraying emphasizes breadth across accounts; guessing emphasizes repeated attempts against an identity. Patterns alone do not reveal passwords used.

3. **Does a successful logon prove compromise?** No. Review preceding events, location/origin context and post-logon activity.

4. **What would you check after a failure-to-success sequence?** Same identity/source/target, time ordering, password-reset context and endpoint actions.

5. **What does 4672 prove?** A new session received special privileges; not necessarily new entitlement or malicious escalation.

6. **How do you investigate a service-account anomaly?** Compare normal origins, tasks, targets and schedules; ask owners about migrations and restores.

7. **When would you recommend containment?** When confidence and potential harm justify the business impact, following the organization’s authority and playbook.

8. **How do you preserve evidence?** Record exact queries/timezone/time bounds, raw event IDs and scoped host/channel context, exports and integrity hashes.

9. **How do you handle conflicting evidence?** Document competing hypotheses, confidence and missing telemetry; escalate uncertainty explicitly.

10. **How do you prioritize a vulnerable affected endpoint?** Combine asset criticality, exposure, exploitation evidence and vulnerability context. This lab provides no scanner or exploit-validation evidence.

## Five detection engineering questions

1. **How do you choose thresholds?** Start with hypotheses and baselines, test expected positives and benign cases, measure noise and document residual blind spots.

2. **Why do bucket boundaries matter?** A burst split across fixed buckets may miss a threshold; rolling windows reduce that specific gap.

3. **How do you avoid duplicate alerts?** Define grouping, overlapping lookback and candidate horizon, suppression and persistent evidence-based deduplication.

4. **How do you measure detection quality?** Use labeled test cases, coverage, false-positive review and known misses. Do not claim recall from an unlabeled sample.

5. **What does MITRE mapping mean?** A behavior hypothesis mapped to a technique; it is not proof an adversary performed it.

## Five Python automation questions

1. **Why use a dictionary for counters?** Keys map identities or sources to values, avoiding repeated full-list searches.

2. **Why separate functions?** Parsing, validation, correlation and export can be understood and tested independently.

3. **How do you handle malformed records?** Validate schema and types, fail clearly and avoid silently exporting partial conclusions.

4. **How do you test time-window logic?** Use independent fixtures covering boundaries, reverse ordering, same timestamps and separate correlation keys.

5. **How do you handle API secrets and errors?** Environment credentials, verified TLS, GET-only reads, timeout handling, response validation and no secret logging.

## Five Sentinel transfer questions

1. **How would you translate stats to KQL?** Use summarize, grouping and count/countif/dcount; verify approximation and field roles.

2. **Is an index equivalent to a Sentinel table?** Not directly. Workspaces and tables represent different storage and schema boundaries.

3. **How would you port a Windows detection?** Verify connector/table schema, normalize subject/target identities and time, then test query and analytics-rule settings.

4. **How would Defender XDR enrich this investigation?** Correlate device logon, process and identity evidence using actual tenant schema. This is proposed work, not completed integration.

5. **What changes when a query becomes an analytics rule?** Add scheduling, lookback, entity mapping, grouping, suppression, severity and an analyst response process.

## My evidence log
Fill this in only after doing the work yourself.

| Area | My notes | Evidence / date |
| --- | --- | --- |
| What I personally implemented | [Fill in] | |
| What I investigated | [Fill in] | |
| What I learned | [Fill in] | |
| Problems I encountered | [Fill in] | |
| How I resolved them | [Fill in] | |
| What I would improve | [Fill in] | |

## Honest interview framing
“This is a simulated SOC lab using synthetic Windows authentication records. I used generated scaffolding for the query library and automation. I personally [fill in completed actions] and validated [fill in evidence]. I have not yet [fill in remaining work].”

Do not present generated queries as queries you personally authored, fixture tests as Splunk validation, or this training as production incident-response experience. Discuss assistance candidly and explain the logic you understand. Update this section as you build independent skill.
