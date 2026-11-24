# Splunk SOC authentication investigation lab

A simulated SOC training project for learning authentication investigation, detection engineering and Python security automation. This is **not production security operations experience**. The analyst performs the investigation; the project supplies reusable queries, candidate rules, offline tools and blank documentation.

## Current status
- Original 1,000-event dataset and instructor materials preserved without regeneration.
- Twelve SPL investigations and five detection candidates authored, each with explanatory notes.
- Standard-library Python CSV/JSON triage and optional GET-only Splunk results integration implemented.
- Python tests use independent fictional fixtures and mocked HTTP responses.
- Saved screenshots document manually executed authentication investigations. Library SPL files and scheduled-rule behavior still require individual runtime validation; Sentinel examples and live API access remain unvalidated.
- [INC-001](docs/incidents/INC-001-quinn-bell.md) documents the analyst-led investigation, supported by ten saved screenshots across the project. Read the case report only after your own blind investigation. No containment or remediation is claimed.

## Technologies and environment
Splunk Enterprise, SPL, Python 3.9+, CSV, JSON, HTTPS REST and unittest. Sentinel/KQL and Defender XDR concepts are documented for transfer; those platforms are not deployed or connected here.

NorthSound Components is a fictional Texas enterprise. The sample spans November 16–22, 2026 (UTC−06:00): 50 employees across IT, Finance, HR, Engineering and Sales; five service identities; fifteen Windows endpoints, three servers and two domain controllers. Internal systems use private IPs; all simulated external addresses use documentation ranges. Both benign and suspicious behavior exist; reserved ranges and unusual hours alone do not establish intent.

The thirteen-field normalized schema includes timestamp, EventCode, identity, source address, emitting host, logon type, authentication package, workstation, status, failure reason, department, synthetic country and a lab-unique EventRecordID. This is sampled teaching data, not raw Windows XML or a full audit trail. Source context on related events is enriched; no session identifiers or corroborating process telemetry are included.

## Layout
| Path | Purpose |
| --- | --- |
| soc_authentication_logs.csv | Original canonical dataset; path preserved for existing imports |
| data/ | Independent example fixture and private optional exports |
| queries/ | Twelve .spl files with matching explanations |
| detections/ | Five candidate .spl rules and rule documentation |
| scripts/ | Offline analyzer and optional REST results reader |
| tests/ | Unit tests using unrelated events and mocked HTTP |
| reports/ | Blank report template; private findings stay ignored |
| screenshots/ | Your manually captured validation screenshots |
| docs/ | Original setup, automation walkthrough, checklist, alerts and Sentinel transfer |
| INTERVIEW_PREP.md | 35 study questions and your blank evidence log |

The original `generate_logs.py` and `instructor_answer_key.json` remain local and are excluded from Git. The generator contains instructor-only construction logic. Keep both closed during your blind investigation. Do not regenerate or move the canonical CSV.

## Setup
1. Use the [Splunk setup guide](docs/SPLUNK_SETUP.md) to create `soc_lab`, configure `soc:windows:auth:csv` and import the CSV **once**. The dataset is already provided; regeneration is unnecessary. Your existing import may use different selectors: the saved evidence uses `index=main sourcetype="Soc_Authentication_csv"`. Adjust library selectors to match the intended import rather than re-uploading solely to change names.
2. Select All time or the fixed historical window. Verify 1,000 total events, 1,000 distinct identifiers, 55 accounts and 20 emitting hosts. Check `_time` and all field extractions.
3. Run local unit tests from this folder:

```sh
python3 -m unittest discover -s tests -v
```

No packages need installation. No Python test reads the answer key or investigates the original dataset.

## Investigation workflow
Start with [the checklist](docs/INVESTIGATION_CHECKLIST.md), then run basic failure/success inventory queries yourself. Read each query's companion notes before progressing to time correlations, geographic changes, service origin novelty and privileged session context. Use a copy of [the report template](reports/INCIDENT_REPORT_TEMPLATE.md) to document observations, evidence, alternative explanations and recommendations. Save screenshots yourself; no results are asserted in advance.

## Detection engineering
Each detection documents objective, thresholds, severity, MITRE hypotheses, false positives, tuning, schedule and response. Follow [scheduled alert setup](docs/SCHEDULED_ALERTS.md). The fixed historical dataset requires historical manual testing; live `now()` candidate filters will correctly return no old candidates. Rules are triage hypotheses and require analyst validation before operational use.

## Python automation
Read [automation usage](docs/AUTOMATION.md) and [the line-by-line walkthrough](docs/PYTHON_WALKTHROUGH.md). Try the unrelated demonstration fixture first:

```sh
python3 scripts/analyze_auth.py data/example_events.json --output-dir reports/practice
```

The analyzer validates records, counts failures, correlates time windows, and exports private JSON/CSV candidates. Running it on the blind dataset can disclose leads; defer that until after your manual investigation.

The [REST integration](docs/REST_API.md) reads an already-completed search job using environment credentials and verified HTTPS. It never creates searches, writes Splunk configuration or performs containment. **No requests have been made to your instance; authorize and configure access yourself before running it.**

## Skills practiced and honest evidence
Query construction, time correlation, authentication semantics, baseline comparison, detection tuning, Python validation/testing, JSON/REST handling and incident documentation. Enrichment and vulnerability prioritization are conceptual extension points, not implemented live integrations. Use [interview preparation](INTERVIEW_PREP.md) to record what you personally executed and understood. Generated scaffolding alone is not evidence of validated detections or completed investigations.

## GitHub preparation
Reviewed source, documentation, the synthetic CSV, the analyst report and ten explicitly approved screenshots are included in version control. Instructor files, credentials, private exports and future unreviewed screenshots remain excluded. Review `.gitignore` and staged changes before adding new evidence. The case report contains investigation findings; readers can practice blindly by deferring it. No GitHub remote is configured and nothing has been pushed.

## Next hands-on tasks
1. Verify ingestion and field/time parsing, capture your own screenshot, and record the exact validation search and counts.
2. Execute the first four investigative queries, explain each pipeline in your own words and record baseline observations without consulting the key.
3. Select one detection, test its historical form in Splunk, examine benign alternatives and document the evidence and tuning in a fresh report.
