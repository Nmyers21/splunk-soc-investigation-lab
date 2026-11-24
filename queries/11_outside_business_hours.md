# Nonbusiness-hour activity
Status: authored; not executed or validated in Splunk.

## Purpose and commands
substr reads the timestamp local clock; strptime/strftime derive its calendar weekday; where selects outside 08:00–18:00 or weekends.

## Required fields
_time, timestamp, EventRecordID, EventCode, Account_Name, ComputerName, Workstation_Name. `_time` must come from the CSV timestamp. All queries use index `soc_lab` and source type `soc:windows:auth:csv`; adjust these selectors if your import differs.

## Interpretation
Clock policy assumes this fixed-offset Texas dataset. Do not use this timestamp-string method for mixed timezone production logs.

## False positives
Shift work, remote staff and automation.

## Sentinel adaptation
Convert UTC using datetime_utc_to_local(TimeGenerated,"America/Chicago"), then datetime_part and dayofweek. Field mappings and runnable examples are in [Sentinel transfer](../docs/SENTINEL_TRANSFER.md). Verify actual connector schema and account roles before porting.

Run over All time for this historical dataset. `sort 0` removes sorting limits for the small lab; large production searches need bounded windows and performance tuning. Rolling statistics remain subject to Splunk streamstats memory/window limits. Local business-hour calculations intentionally use the timestamp's -06:00 clock.
