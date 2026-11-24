# Transfer from Splunk to Microsoft Sentinel
This lab builds transferable investigation and correlation skills. It does not establish hands-on Sentinel, Defender XDR or production response experience. All examples below are authored and unvalidated in either platform.

| Splunk concept | Sentinel / Log Analytics counterpart | Practical distinction |
| --- | --- | --- |
| SPL pipeline | KQL pipeline | Similar filtering/aggregation intent, different operators and evaluation rules |
| Index | Workspace and tables | An index is a storage/search boundary; it is not a one-to-one synonym for a Log Analytics table |
| Search | Logs query | Select appropriate tables, time bounds and connector schema |
| Saved search / alert | Scheduled analytics rule | Query plus rule schedule, lookback, entity mapping, grouping and suppression |
| Triggered alert and analyst workflow | Alerts grouped into incidents | Incident grouping, investigation graph and automation are separately configured |
| `_time` | `TimeGenerated` | Parsed source event time must be verified |
| `stats`, `dc`, `values` | `summarize`, `dcount`, `make_set` | dcount can be approximate; verify cardinality expectations |
| `eval`, `table`, `sort` | `extend`, `project`, `sort by` | Function names, nulls, type conversion and ordering differ |

## Schema matters
`SecurityEvent` is an example Windows-event table, depending on configured connectors. `WindowsEvent` and custom ingested CSV tables have different shapes. These examples assume SecurityEvent; do not paste the original CSV into Sentinel and expect that table to appear. Normalize the identity according to event role: target identity for 4624/4625 and subject identity for 4672. `Account` may include a domain while `TargetUserName` does not. Avoid mixing these without domain-aware normalization. The `Source_Country` enrichment does not exist as a universal Windows SecurityEvent field.

| Lab field | Example SecurityEvent field | Caveat |
| --- | --- | --- |
| EventCode | EventID | Integer type |
| Account_Name | TargetUserName or SubjectUserName | Event-specific role; do not assume Account always identifies the target |
| Source_Network_Address | IpAddress | May be blank or absent on related events |
| ComputerName | Computer | Often FQDN; normalize carefully |
| Logon_Type | LogonType | Convert to integer if necessary |
| Workstation_Name | WorkstationName | Collector/event dependent |
| timestamp / `_time` | TimeGenerated | Usually UTC |
| EventRecordID | EventRecordId or source event data | Verify actual schema; scope native ID with host/channel |

## Five equivalent examples
Use All time / the fixed lab date window in Splunk. Sentinel examples use equivalent UTC bounds for November 16–22 Central. Replace bounds and selectors for your environment. These are teaching queries, not validated analytics rules.

### 1. Failures by account
```spl
index=soc_lab sourcetype="soc:windows:auth:csv" EventCode=4625
| stats count AS failures by Account_Name
| sort - failures
```
```kusto
SecurityEvent
| where TimeGenerated >= datetime(2026-11-16T06:00:00Z) and TimeGenerated < datetime(2026-11-23T06:00:00Z)
| where EventID == 4625
| summarize failures=count() by TargetUserName
| sort by failures desc
```

### 2. Successful remote interactive logons
```spl
index=soc_lab sourcetype="soc:windows:auth:csv" EventCode=4624 Logon_Type=10
| stats count AS successes by Account_Name ComputerName
```
```kusto
SecurityEvent
| where TimeGenerated >= datetime(2026-11-16T06:00:00Z) and TimeGenerated < datetime(2026-11-23T06:00:00Z)
| where EventID == 4624 and toint(LogonType) == 10
| summarize successes=count() by TargetUserName, Computer
```

### 3. Source breadth in fixed thirty-minute buckets
This is a bucketed triage approximation in both languages; it differs from the rolling production-candidate SPL file.
```spl
index=soc_lab sourcetype="soc:windows:auth:csv" EventCode=4625
| bin _time span=30m
| stats dc(Account_Name) AS accounts count AS failures by _time Source_Network_Address
| where accounts>=10
```
```kusto
SecurityEvent
| where TimeGenerated >= datetime(2026-11-16T06:00:00Z) and TimeGenerated < datetime(2026-11-23T06:00:00Z)
| where EventID == 4625 and isnotempty(IpAddress) and isnotempty(TargetUserName)
| summarize accounts=dcount(TargetUserName), failures=count() by bin(TimeGenerated,30m), IpAddress
| where accounts >= 10
```

### 4. Privileged sessions by account and computer
```spl
index=soc_lab sourcetype="soc:windows:auth:csv" EventCode=4672
| stats count AS privileged_sessions by Account_Name ComputerName
```
```kusto
SecurityEvent
| where TimeGenerated >= datetime(2026-11-16T06:00:00Z) and TimeGenerated < datetime(2026-11-23T06:00:00Z)
| where EventID == 4672
| summarize privileged_sessions=count() by SubjectUserName, Computer
```
4672 reflects special privileges in a session. Additional event types and endpoint evidence are needed to establish escalation.

### 5. After-hours successful logons
```spl
index=soc_lab sourcetype="soc:windows:auth:csv" EventCode=4624
| eval local_hour=tonumber(substr(timestamp,12,2))
| where local_hour<8 OR local_hour>=18
| table _time Account_Name ComputerName local_hour
```
```kusto
SecurityEvent
| where TimeGenerated >= datetime(2026-11-16T06:00:00Z) and TimeGenerated < datetime(2026-11-23T06:00:00Z)
| where EventID == 4624
| extend local_time=datetime_utc_to_local(TimeGenerated,"America/Chicago")
| extend local_hour=datetime_part("hour",local_time)
| where local_hour < 8 or local_hour >= 18
| project TimeGenerated, TargetUserName, Computer, local_hour
```
The SPL version uses this dataset's fixed timestamp offset; the KQL timezone conversion handles daylight-saving rules. Mixed timezone source strings require a different SPL approach.

## Defender, enrichment and vulnerability context
Defender XDR tables such as DeviceLogonEvents, DeviceProcessEvents and DeviceInfo can corroborate identity behavior with device/process context, but are not interchangeable with SecurityEvent. Advanced Hunting may use Timestamp and AccountName and product-specific action types. Validate documentation and tenant schema before writing detections. An alert enrichment workflow can attach asset owner, identity role, existing incidents and vulnerability exposure. Vulnerability severity alone does not establish exploitation: prioritize by exposure, exploitability, asset criticality and observed activity. This project does not ingest Defender telemetry, perform vulnerability scans or validate live enrichment integrations.

Sources: [SecurityEvent schema](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityevent), [official sample SecurityEvent queries](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/queries/securityevent), [KQL overview](https://learn.microsoft.com/en-us/kusto/query/), [Defender Advanced Hunting schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables).
