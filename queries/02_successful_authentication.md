# Success inventory
Status: authored; not executed or validated in Splunk.

## Purpose and commands
Aggregates successful logons by identity and destination, retaining logon types.

## Required fields
EventCode, Account_Name, ComputerName, Logon_Type. `_time` must come from the CSV timestamp. All queries use index `soc_lab` and source type `soc:windows:auth:csv`; adjust these selectors if your import differs.

## Interpretation
Compare interactive versus network use and expected destinations.

## False positives
Legitimate service and remote work.

## Sentinel adaptation
where EventID == 4624; summarize count(), make_set(LogonType) by TargetUserName, Computer. Field mappings and runnable examples are in [Sentinel transfer](../docs/SENTINEL_TRANSFER.md). Verify actual connector schema and account roles before porting.

Run over All time for this historical dataset. `sort 0` removes sorting limits for the small lab; large production searches need bounded windows and performance tuning. Rolling statistics remain subject to Splunk streamstats memory/window limits. Local business-hour calculations intentionally use the timestamp's -06:00 clock.
