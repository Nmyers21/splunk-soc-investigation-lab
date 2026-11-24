# Brute-force candidate
Status: authored; not executed or validated in Splunk.

## Purpose and commands
streamstats counts failures over ten minutes per account, source and target after chronological sorting.

## Required fields
_time, EventRecordID, EventCode, Account_Name, Source_Network_Address, ComputerName. `_time` must come from the CSV timestamp. All queries use index `soc_lab` and source type `soc:windows:auth:csv`; adjust these selectors if your import differs.

## Interpretation
Ten failures is a starting threshold. Multiple rows can describe the same burst.

## False positives
Stale credentials, client loops and user recovery.

## Sentinel adaptation
Join failures on identity/source/target and constrain time distance, or start with summarize count() by bin(TimeGenerated,10m) with documented boundary limits. Field mappings and runnable examples are in [Sentinel transfer](../docs/SENTINEL_TRANSFER.md). Verify actual connector schema and account roles before porting.

Run over All time for this historical dataset. `sort 0` removes sorting limits for the small lab; large production searches need bounded windows and performance tuning. Rolling statistics remain subject to Splunk streamstats memory/window limits. Local business-hour calculations intentionally use the timestamp's -06:00 clock.
