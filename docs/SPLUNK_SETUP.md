# NorthSound Components SOC authentication lab

A blind investigation dataset for Splunk Enterprise. NorthSound Components is a fictional mid-sized manufacturing and software company headquartered in Texas. This is a sampled, normalized seven-day audit extract, not the company's complete event volume.

## Dataset availability

The canonical `soc_authentication_logs.csv` is included in the repository. Do not regenerate it to continue the investigation. It contains 1,000 normalized events across November 16–22, 2026, Central Standard Time (UTC−06:00).

The original local generator and instructor answer key remain private and are deliberately excluded from Git because they contain solutions. They are not dependencies for importing the provided CSV or running the automation tools. Keep any local instructor materials closed during a blind investigation.

The analyst's existing import uses `index=main sourcetype="Soc_Authentication_csv"`. The instructions below describe an alternative dedicated `soc_lab` import. If the CSV is already ingested, use your existing selectors and do not import it a second time merely to follow these defaults.

## Enterprise environment

- 50 employee accounts, ten each in IT, Finance, HR, Engineering and Sales.
- Five service accounts: `svc_backup`, `svc_sql`, `svc_monitor`, `svc_deploy`, `svc_report`.
- Fifteen shared Windows endpoints, `NS-WS01` through `NS-WS15`, on `10.24.10.0/24`. Employees share a workstation pool across shifts and hybrid schedules.
- Three servers: `NS-FS01` (files), `NS-SQL01` (database), `NS-APP01` (application and remote access).
- Two domain controllers: `NS-DC01` and `NS-DC02`. Servers and controllers reside on `10.24.20.0/24`.
- Routine office hours are approximately 08:00–18:00 Central, with scheduled automation, maintenance, remote work and some weekend activity.

External addresses use only documentation networks `192.0.2.0/24`, `198.51.100.0/24`, and `203.0.113.0/24`. These represent both legitimate remote clients and other external sources. Do not infer intent from the reserved IP range itself. `Source_Country` is simulated enrichment, including domestic attribution for internal sources; do not replace it using live IP geolocation.

## Event and field semantics

The CSV contains exactly the thirteen requested fields. This is a teaching schema derived from Windows auditing, not native WinEventLog XML and not a full CIM mapping.

| EventCode | Status | Meaning |
| --- | --- | --- |
| 4624 | Success | Successful logon |
| 4625 | Failure | Failed logon; Failure_Reason is populated |
| 4634 | Logoff | Session ended |
| 4648 | Explicit credentials attempted | Credential use attempt, without implying target authentication success |
| 4672 | Special privileges assigned | Privileged new session; does not itself show a privilege or group membership change |

Logon types are 2 (interactive), 3 (network), and 10 (remote interactive). `ComputerName` is the emitting host; `Workstation_Name` is the origin, or `-` when unavailable. `Account_Name` identifies the relevant target identity, including the supplied identity for 4648. Department comes from the identity directory.

For 4634 and 4672, source address, workstation, authentication package and logon type are normalized context inherited from their related logon. These values are not necessarily native fields on those raw Windows events. Similar normalization supplies logon type and authentication package on 4648. EventRecordID is unique across this lab extract; native Windows record IDs are normally scoped to a host and event log. Without a Logon_ID field, correlation by account, target, origin and time is approximate.

## Create the index

Sign in to Splunk Web with an account allowed to manage indexes. Open **Settings → Indexes → New Index**. Set the index name to `soc_lab`, select the **Events** data type, leave storage paths at their defaults, and save. Ensure your search role can search this index.

## Import the CSV

1. Open **Settings → Add Data → Upload** and select `soc_authentication_logs.csv` only.
2. In **Set Source Type**, start from the structured **csv** type. Verify comma delimiters, one header row and thirteen extracted fields. Save a custom source type named `soc:windows:auth:csv`.
3. Set timestamp extraction to the `timestamp` field. Use format `%Y-%m-%dT%H:%M:%S%:z` for the ISO timestamp with a colon in the UTC offset. The explicit `-06:00` takes precedence over the machine timezone. Confirm the preview shows November 2026 event times rather than import time.
4. In the advanced source-type settings, use the equivalent configuration below. Header handling must leave the header out of the event count.
5. On **Input Settings**, choose index `soc_lab`. The input-level host can be `northsound-lab`; use `ComputerName` for the emitting Windows computer in searches.
6. Review and submit once. Re-uploading the same file will create duplicate indexed events. Do not upload the answer key or the Python source.

Equivalent source-type stanza for a single-instance Enterprise lab:

```ini
[soc:windows:auth:csv]
INDEXED_EXTRACTIONS = csv
FIELD_DELIMITER = ,
HEADER_FIELD_LINE_NUMBER = 1
TIMESTAMP_FIELDS = timestamp
TIME_FORMAT = %Y-%m-%dT%H:%M:%S%:z
SHOULD_LINEMERGE = false
KV_MODE = none
```

If your version's upload wizard uses different labels, configure the advanced properties and inspect the preview before submitting. For file-based setup, place this stanza in an app's `local/props.conf` on the instance that first reads the CSV, then restart that instance. Distributed forwarder deployments require structured parsing settings at the reader, rather than only at the receiving indexer. The CSV should retain its header.

Reference: [Splunk structured data extraction](https://help.splunk.com/en/splunk-enterprise/get-data-in/get-started-with-getting-data-in/9.3/configure-indexed-field-extraction/extract-fields-from-files-with-structured-data) and [props.conf specification](https://help.splunk.com/en/data-management/splunk-enterprise-admin-manual/10.6/configuration-file-reference/10.6.0-configuration-file-reference/props.conf).

## Verify ingestion

Open Search & Reporting and select **All time**, since this is a fixed historical dataset:

```spl
index=soc_lab sourcetype="soc:windows:auth:csv"
| stats count AS events dc(EventRecordID) AS unique_events
    dc(Account_Name) AS accounts dc(ComputerName) AS computers
    min(_time) AS first_event max(_time) AS last_event
| convert ctime(first_event) ctime(last_event)
```

Expect 1,000 events, 1,000 unique identifiers, 55 accounts and 20 emitting computers. Displayed times follow your Splunk user's timezone. Confirm dates fall within November 16–22 in America/Chicago. If counts differ, check the index, source type, time picker and whether the file was uploaded more than once. If dates are wrong, fix parsing before reimporting into a clean lab index; changing source-type settings does not rewrite existing indexed timestamps.

Start your investigation with your own questions and hypotheses. Baseline users, hosts and service behavior, correlate nearby events and document evidence plus alternative explanations. This README intentionally contains no incident solutions.
