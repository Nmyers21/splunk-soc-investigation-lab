# Password-spray candidate
Status: authored; not executed or validated in Splunk.

## Purpose and commands
sort ensures event order; streamstats maintains a thirty-minute rolling count and distinct-account set per source; where selects at least ten accounts.

## Required fields
_time, EventRecordID, EventCode, Account_Name, Source_Network_Address. `_time` must come from the CSV timestamp. All queries use index `soc_lab` and source type `soc:windows:auth:csv`; adjust these selectors if your import differs.

## Interpretation
Rows are threshold-crossing evidence, not separate incidents; correlate and deduplicate. Password values are unavailable, so spraying remains a hypothesis.

## False positives
Authorized audits and shared gateways.

## Sentinel adaptation
Use a time-window self-join or sliding-window aggregation; dcount usernames by source. A bin-based approximation has boundary blind spots. Field mappings and runnable examples are in [Sentinel transfer](../docs/SENTINEL_TRANSFER.md). Verify actual connector schema and account roles before porting.

Run over All time for this historical dataset. `sort 0` removes sorting limits for the small lab; large production searches need bounded windows and performance tuning. Rolling statistics remain subject to Splunk streamstats memory/window limits. Local business-hour calculations intentionally use the timestamp's -06:00 clock.
