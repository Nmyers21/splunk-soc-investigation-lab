# Failure source inventory
Status: authored; not executed or validated in Splunk.

## Purpose and commands
stats counts failures and distinct accounts by source address.

## Required fields
EventCode, Source_Network_Address, Account_Name, ComputerName. `_time` must come from the CSV timestamp. All queries use index `soc_lab` and source type `soc:windows:auth:csv`; adjust these selectors if your import differs.

## Interpretation
High breadth can suggest a shared source or distributed user population.

## False positives
VPN gateways, NAT and authentication proxies.

## Sentinel adaptation
summarize failures=count(), accounts=dcount(TargetUserName) by IpAddress. Field mappings and runnable examples are in [Sentinel transfer](../docs/SENTINEL_TRANSFER.md). Verify actual connector schema and account roles before porting.

Run over All time for this historical dataset. `sort 0` removes sorting limits for the small lab; large production searches need bounded windows and performance tuning. Rolling statistics remain subject to Splunk streamstats memory/window limits. Local business-hour calculations intentionally use the timestamp's -06:00 clock.
