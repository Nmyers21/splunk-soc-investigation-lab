# Account triage overview
Status: authored; not executed or validated in Splunk.

## Purpose and commands
stats calculates independent indicators per account; where identifies accounts worth reviewing; eval explicitly describes uncertainty.

## Required fields
EventCode, Account_Name, Source_Country, Source_Network_Address. `_time` must come from the CSV timestamp. All queries use index `soc_lab` and source type `soc:windows:auth:csv`; adjust these selectors if your import differs.

## Interpretation
Whole-window aggregation does not establish sequencing or compromise. Do not classify an account solely from this table.

## False positives
Admins, services, travel and password recovery.

## Sentinel adaptation
summarize countif(EventID == 4625), countif(EventID == 4624), countif(EventID == 4672), dcount(country) by normalized account; where applies triage logic. Field mappings and runnable examples are in [Sentinel transfer](../docs/SENTINEL_TRANSFER.md). Verify actual connector schema and account roles before porting.

Run over All time for this historical dataset. `sort 0` removes sorting limits for the small lab; large production searches need bounded windows and performance tuning. Rolling statistics remain subject to Splunk streamstats memory/window limits. Local business-hour calculations intentionally use the timestamp's -06:00 clock.
