# Privilege context
Status: authored; not executed or validated in Splunk.

## Purpose and commands
Rolling counts correlate failures/logons with 4672; case annotates context; table presents evidence.

## Required fields
_time, timestamp, EventRecordID, EventCode, Account_Name, Source_Network_Address, ComputerName. `_time` must come from the CSV timestamp. All queries use index `soc_lab` and source type `soc:windows:auth:csv`; adjust these selectors if your import differs.

## Interpretation
4672 means privileges assigned to a session; it does not prove escalation or changed group membership.

## False positives
Routine administration, emergency maintenance and services.

## Sentinel adaptation
Filter EventID == 4672; correlate prior 4624/4625 by identity, Computer and preferably LogonId. Source enrichment may be required. Field mappings and runnable examples are in [Sentinel transfer](../docs/SENTINEL_TRANSFER.md). Verify actual connector schema and account roles before porting.

Run over All time for this historical dataset. `sort 0` removes sorting limits for the small lab; large production searches need bounded windows and performance tuning. Rolling statistics remain subject to Splunk streamstats memory/window limits. Local business-hour calculations intentionally use the timestamp's -06:00 clock.
