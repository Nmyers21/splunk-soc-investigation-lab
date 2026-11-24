# High-failure identities
Status: authored; not executed or validated in Splunk.

## Purpose and commands
bin builds fixed fifteen-minute buckets; stats counts per account; where applies ten-event threshold.

## Required fields
_time, EventCode, Account_Name, Source_Network_Address. `_time` must come from the CSV timestamp. All queries use index `soc_lab` and source type `soc:windows:auth:csv`; adjust these selectors if your import differs.

## Interpretation
Bucket boundaries can split a burst; use rolling brute-force logic for a stronger follow-up.

## False positives
Password changes and stale clients.

## Sentinel adaptation
summarize failures=count() by TargetUserName, bin(TimeGenerated,15m); where failures >= 10. Field mappings and runnable examples are in [Sentinel transfer](../docs/SENTINEL_TRANSFER.md). Verify actual connector schema and account roles before porting.

Run over All time for this historical dataset. `sort 0` removes sorting limits for the small lab; large production searches need bounded windows and performance tuning. Rolling statistics remain subject to Splunk streamstats memory/window limits. Local business-hour calculations intentionally use the timestamp's -06:00 clock.
