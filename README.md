# Splunk SOC authentication investigation

A hands-on investigation of synthetic Windows authentication activity using **Splunk Enterprise**, documented with screenshots and an incident response report. This is a simulated training project, not production security operations experience.

## Completed work

- Analyzed failed authentication counts by account and source address.
- Correlated failed and successful logons using identity, source, destination, timestamps and logon type.
- Compared suspicious activity against earlier account behavior and reviewed subsequent authentication records.
- Investigated source activity across multiple accounts and tested a fifteen-minute aggregation query.
- Captured a password-spraying alert configuration. The screenshot documents configuration, not proof that a scheduled alert ran or triggered.
- Developed an incident report explaining findings, uncertainty, severity, alternative explanations and recommended response actions.

## Incident write-up

Read [INC-001: Suspected account compromise involving quinn.bell](docs/incidents/INC-001-quinn-bell.md).

The report includes the investigation timeline, searches actually shown in the evidence, six embedded screenshots, confidence assessment and recommended containment/remediation. Authentication success is established in the simulated records; unauthorized access remains unconfirmed. No containment or remediation is claimed as performed.

This repository demonstrates practical Splunk experience through authentication log analysis, evidence correlation, saved search results and a structured incident response report. The report separates observed findings from proposed improvements and recommended response actions.

## Evidence

All ten saved captures are available in [screenshots](screenshots/README.md). They cover account/source failure counts, authentication timelines, subsequent activity, account breadth and alert configuration. The SPL reproduced in screenshots and the incident report documents the searches used in Splunk.

## Dataset and environment

The provided `soc_authentication_logs.csv` contains 1,000 synthetic events spanning November 16–22, 2026, Central Standard Time (UTC−06:00). The fictional enterprise includes 50 employee accounts, five service accounts, fifteen Windows endpoints, three servers and two domain controllers.

The thirteen fields capture timestamp, event code, identity, source address, emitting host, logon type, authentication package, workstation, status, failure reason, department, synthetic country and lab-unique event ID. Private addresses represent internal systems; documentation addresses represent simulated external sources. The sample is a normalized teaching extract, not complete Windows auditing or endpoint telemetry.

## Reproduce the manual investigation

1. Follow [Splunk setup](docs/SPLUNK_SETUP.md). If the CSV is already imported, reuse the existing import rather than ingesting it twice.
2. The saved investigation uses `index=main sourcetype="Soc_Authentication_csv"`. Substitute your actual selectors if different.
3. Select All time or the fixed historical period and confirm timestamp parsing and field extraction.
4. Run the evidence-backed searches in the incident report and compare your findings with the screenshots.
5. Use [the investigation checklist](docs/INVESTIGATION_CHECKLIST.md) to document alternative explanations, missing information and confidence.

Reading the report reveals this case's findings. For a blind exercise, investigate the CSV before opening the write-up or screenshots.

## Repository contents

| Path | Purpose |
| --- | --- |
| `soc_authentication_logs.csv` | Original synthetic authentication dataset |
| `docs/incidents/INC-001-quinn-bell.md` | Analyst incident report |
| `docs/SPLUNK_SETUP.md` | Manual import and field/time configuration |
| `docs/INVESTIGATION_CHECKLIST.md` | Authentication investigation checklist |
| `screenshots/` | Ten saved Splunk evidence captures |

## Skills demonstrated

Manual SIEM investigation, SPL filtering/aggregation, Windows authentication interpretation, chronological evidence correlation, assessment of false positives, distinction between suspicion and confirmed compromise, and incident documentation.

Python automation, API integration, reusable code libraries and automated tests are outside the current portfolio scope. Future automation and detection changes described in the report remain recommendations rather than completed work.

## Publication status

This repository is public and presents a simulated Splunk investigation with supporting evidence and an incident report. Instructor materials, credentials, private exports and unused learning components are excluded from the current tracked files. Existing screenshot names and dataset bytes are preserved.
