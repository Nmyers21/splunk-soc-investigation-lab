# Failure inventory
Status: authored; not executed or validated in Splunk.

## Purpose and commands
Aggregates failures per identity, origin and destination. stats groups records; values preserves distinct reasons; sort ranks volume.

## Required fields
EventCode, Account_Name, Source_Network_Address, ComputerName, Failure_Reason. `_time` must come from the CSV timestamp. All queries use index `soc_lab` and source type `soc:windows:auth:csv`; adjust these selectors if your import differs.

## Interpretation
Counts are workload and triage context, not proof of attack.

## False positives
Mistyped or cached passwords.

## Sentinel adaptation
where EventID == 4625; summarize count() by TargetUserName, IpAddress, Computer. Field mappings and runnable examples are in [Sentinel transfer](../docs/SENTINEL_TRANSFER.md). Verify actual connector schema and account roles before porting.

Run over All time for this historical dataset. `sort 0` removes sorting limits for the small lab; large production searches need bounded windows and performance tuning. Rolling statistics remain subject to Splunk streamstats memory/window limits. Local business-hour calculations intentionally use the timestamp's -06:00 clock.
