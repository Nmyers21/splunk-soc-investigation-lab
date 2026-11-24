# Geographic transition
Status: authored; not executed or validated in Splunk.

## Purpose and commands
streamstats current=f carries previous country/time per account; eval computes elapsed time; where filters changed countries within one hour.

## Required fields
_time, EventRecordID, EventCode, Account_Name, Source_Country. `_time` must come from the CSV timestamp. All queries use index `soc_lab` and source type `soc:windows:auth:csv`; adjust these selectors if your import differs.

## Interpretation
A location change is a lead, not proof of impossible travel. This uses synthetic enrichment.

## False positives
VPN changes, geolocation errors and shared accounts.

## Sentinel adaptation
Enrich SecurityEvent before using country; sort and serialize with prev plus an account boundary check, or use SigninLogs LocationDetails under a separate schema. Field mappings and runnable examples are in [Sentinel transfer](../docs/SENTINEL_TRANSFER.md). Verify actual connector schema and account roles before porting.

Run over All time for this historical dataset. `sort 0` removes sorting limits for the small lab; large production searches need bounded windows and performance tuning. Rolling statistics remain subject to Splunk streamstats memory/window limits. Local business-hour calculations intentionally use the timestamp's -06:00 clock.
