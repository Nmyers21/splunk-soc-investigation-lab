# Failure-to-success correlation
Status: authored; not executed or validated in Splunk.

## Purpose and commands
streamstats counts preceding failures in fifteen minutes; last tracks the latest failure timestamp; where requires a later success on the same identity/source/target.

## Required fields
_time, EventRecordID, EventCode, Account_Name, Source_Network_Address, ComputerName. `_time` must come from the CSV timestamp. All queries use index `soc_lab` and source type `soc:windows:auth:csv`; adjust these selectors if your import differs.

## Interpretation
At least five failures precede a success. Not necessarily consecutive: the rolling count includes failures before intervening successes. Equal-time rows cannot prove order and are excluded.

## False positives
Successful recovery after typing errors or password reset.

## Sentinel adaptation
Join failure rows to successes on normalized identity/source/target, require failure time < success time and <=15m, summarize by success record ID. Field mappings and runnable examples are in [Sentinel transfer](../docs/SENTINEL_TRANSFER.md). Verify actual connector schema and account roles before porting.

Run over All time for this historical dataset. `sort 0` removes sorting limits for the small lab; large production searches need bounded windows and performance tuning. Rolling statistics remain subject to Splunk streamstats memory/window limits. Local business-hour calculations intentionally use the timestamp's -06:00 clock.
