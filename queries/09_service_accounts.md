# Service origin novelty
Status: authored; not executed or validated in Splunk.

## Purpose and commands
Two streamstats passes compute prior activity for the service account and account/origin pair; requires three prior account events and no earlier matching origin.

## Required fields
_time, EventRecordID, EventCode, Account_Name, Workstation_Name, ComputerName. `_time` must come from the CSV timestamp. All queries use index `soc_lab` and source type `soc:windows:auth:csv`; adjust these selectors if your import differs.

## Interpretation
First-seen within the selected search window only. Prefix is a lab convention, not a service-identity inventory. A scheduled fifteen-minute search is too short to learn a reliable baseline.

## False positives
Migrations, restore tests and short history.

## Sentinel adaptation
Normalize service identities; compare current origins with an earlier baseline using a leftanti join. Field mappings and runnable examples are in [Sentinel transfer](../docs/SENTINEL_TRANSFER.md). Verify actual connector schema and account roles before porting.

Run over All time for this historical dataset. `sort 0` removes sorting limits for the small lab; large production searches need bounded windows and performance tuning. Rolling statistics remain subject to Splunk streamstats memory/window limits. Local business-hour calculations intentionally use the timestamp's -06:00 clock.
