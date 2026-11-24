# Python walkthrough: analyze_auth.py

Read this alongside [the source](../scripts/analyze_auth.py). It describes the current file line by line, including imports, comments and continuation lines. Blank lines only separate ideas.

## Concepts to understand first
- **Dictionary:** key → value mapping. `event["Account_Name"]` retrieves a value; the key is not a list position. `dict(...)` creates a dictionary.
- **Counter:** a dictionary specialized for counts; `failed_users[user] += 1` increments a per-user number.
- **List:** ordered collection. `findings.append(finding)` adds one dictionary at the end of the list. The list itself is not a dictionary.
- **Set:** unique values; used for event IDs, observed origins and duplicate suppression.
- **Deque:** double-ended queue. `append` adds newest history and `popleft` removes oldest history efficiently.
- **Loops:** `for` visits items; `while` repeats while its condition stays true.
- **Conditions:** `if`/`elif` choose behavior; comparisons test values, while `=` assigns a value.
- **Functions:** inputs enter through parameters; `return` supplies a result. The nested `emit` helper can access its enclosing function’s lists/sets.
- **Files:** `with ... open(...)` ensures closing; CSV readers/writers handle quoting and newlines.
- **JSON:** `load` parses file text into Python objects; `dumps` serializes objects into text. JSON is a representation, not a network request.
- **Exceptions:** validation raises ValueError; `try`/`except` converts expected errors to a failed exit code. Tests assert these failure behaviors.

## Data flow
`main` parses arguments → `load_events` reads and calls `validate_record` → `analyze` creates counts/candidates → `export_summary` writes JSON/CSV. The analyzer never opens the instructor key.

## Line-by-line reference
| Line | Source | Explanation |
| --- | --- | --- |
| 1 | `#!/usr/bin/env python3` | Allows direct execution on Unix when the file has executable permissions; python3 invocation does not require it. |
| 2 | `"""Offline authentication triage. Produces leads, never compromise verdicts."""` | Docstring describing the module or current function; it documents behavior rather than running detection logic. |
| 3 | `import argparse` | Imports standard-library helpers: import argparse. No third-party package installation is required. |
| 4 | `import csv` | Imports standard-library helpers: import csv. No third-party package installation is required. |
| 5 | `import ipaddress` | Imports standard-library helpers: import ipaddress. No third-party package installation is required. |
| 6 | `import json` | Imports standard-library helpers: import json. No third-party package installation is required. |
| 7 | `import logging` | Imports standard-library helpers: import logging. No third-party package installation is required. |
| 8 | `from collections import Counter, defaultdict, deque` | Imports standard-library helpers: from collections import Counter, defaultdict, deque. No third-party package installation is required. |
| 9 | `from datetime import datetime, timedelta` | Imports standard-library helpers: from datetime import datetime, timedelta. No third-party package installation is required. |
| 10 | `from pathlib import Path` | Imports standard-library helpers: from pathlib import Path. No third-party package installation is required. |
| 12 | `LOG = logging.getLogger(__name__)` | Assigns LOG from the expression shown. Square-bracket access retrieves a dictionary value; literals and calls construct the configured value. |
| 13 | `REQUIRED = ('timestamp EventCode Account_Name Source_Network_Address ComputerName '` | Assigns REQUIRED from the expression shown. Square-bracket access retrieves a dictionary value; literals and calls construct the configured value. |
| 14 | `'Logon_Type Authentication_Package Workstation_Name Status Failure_Reason '` | Continues the expression or call on the preceding line, supplying the displayed values, fields or function arguments. |
| 15 | `'Department Source_Country EventRecordID').split()` | Continues the expression or call on the preceding line, supplying the displayed values, fields or function arguments. |
| 16 | `STATUS = {4624: 'Success', 4625: 'Failure', 4634: 'Logoff',` | Assigns STATUS from the expression shown. Square-bracket access retrieves a dictionary value; literals and calls construct the configured value. |
| 17 | `4648: 'Explicit credentials attempted', 4672: 'Special privileges assigned'}` | Continues the expression or call on the preceding line, supplying the displayed values, fields or function arguments. |
| 18 | `FINDING_FIELDS = ['rule', 'severity', 'account', 'source_ip', 'computer',` | Assigns FINDING_FIELDS from the expression shown. Square-bracket access retrieves a dictionary value; literals and calls construct the configured value. |
| 19 | `'timestamp', 'event_record_ids', 'reason']` | Continues the expression or call on the preceding line, supplying the displayed values, fields or function arguments. |
| 22 | `def validate_record(raw, row_number):` | Defines validate_record as a reusable function; parameters supply inputs and the indented body runs when called. |
| 23 | `"""Copy and normalize one record without modifying the caller's data."""` | Docstring describing the module or current function; it documents behavior rather than running detection logic. |
| 24 | `if not isinstance(raw, dict) or any(field not in raw for field in REQUIRED):` | Conditional: evaluate not isinstance(raw, dict) or any(field not in raw for field in REQUIRED); execute the indented branch only when true. |
| 25 | `raise ValueError(f'Row {row_number}: required fields missing')` | Rejects invalid input with a clear reason. This prevents silently treating malformed records as valid evidence. |
| 26 | `event = {field: raw[field] for field in REQUIRED}` | List/dictionary comprehension builds event by iterating and optionally filtering in one expression. |
| 27 | `if any(value is None or isinstance(value, (dict, list, bool)) for value in event.values()):` | Conditional: evaluate any(value is None or isinstance(value, (dict, list, bool)) for value in event.values()); execute the indented branch only when true. |
| 28 | `raise ValueError(f'Row {row_number}: unsupported field value')` | Rejects invalid input with a clear reason. This prevents silently treating malformed records as valid evidence. |
| 29 | `for field in REQUIRED:` | Loop: field in REQUIRED. Each iteration processes one field, row, event, finding or count entry. |
| 30 | `event[field] = str(event[field]).strip()` | Assigns event[field] from the expression shown. Square-bracket access retrieves a dictionary value; literals and calls construct the configured value. |
| 31 | `for field in ['EventCode', 'Logon_Type', 'EventRecordID']:` | Loop: field in ['EventCode', 'Logon_Type', 'EventRecordID']. Each iteration processes one field, row, event, finding or count entry. |
| 32 | `event[field] = int(event[field])` | Assigns event[field] from the expression shown. Square-bracket access retrieves a dictionary value; literals and calls construct the configured value. |
| 33 | `code = event['EventCode']` | Assigns code from the expression shown. Square-bracket access retrieves a dictionary value; literals and calls construct the configured value. |
| 34 | `if code not in STATUS or event['Status'] != STATUS[code]:` | Conditional: evaluate code not in STATUS or event['Status'] != STATUS[code]; execute the indented branch only when true. |
| 35 | `raise ValueError(f'Row {row_number}: inconsistent event status')` | Rejects invalid input with a clear reason. This prevents silently treating malformed records as valid evidence. |
| 36 | `if bool(event['Failure_Reason']) != (code == 4625):` | Conditional: evaluate bool(event['Failure_Reason']) != (code == 4625); execute the indented branch only when true. |
| 37 | `raise ValueError(f'Row {row_number}: inconsistent failure reason')` | Rejects invalid input with a clear reason. This prevents silently treating malformed records as valid evidence. |
| 38 | `if event['Authentication_Package'] not in ('NTLM', 'Kerberos'):` | Conditional: evaluate event['Authentication_Package'] not in ('NTLM', 'Kerberos'); execute the indented branch only when true. |
| 39 | `raise ValueError(f'Row {row_number}: unsupported authentication package')` | Rejects invalid input with a clear reason. This prevents silently treating malformed records as valid evidence. |
| 40 | `if not 0 <= event['Logon_Type'] <= 13 or event['EventRecordID'] <= 0:` | Conditional: evaluate not 0 <= event['Logon_Type'] <= 13 or event['EventRecordID'] <= 0; execute the indented branch only when true. |
| 41 | `raise ValueError(f'Row {row_number}: invalid numeric value')` | Rejects invalid input with a clear reason. This prevents silently treating malformed records as valid evidence. |
| 42 | `if any(not event[f] for f in ['Account_Name', 'ComputerName', 'Workstation_Name', 'Department', 'Source_Country']):` | Conditional: evaluate any(not event[f] for f in ['Account_Name', 'ComputerName', 'Workstation_Name', 'Department', 'Source_Country']); execute the indented branch only when true. |
| 43 | `raise ValueError(f'Row {row_number}: empty identity or context')` | Rejects invalid input with a clear reason. This prevents silently treating malformed records as valid evidence. |
| 44 | `ipaddress.ip_address(event['Source_Network_Address'])` | Validates the source as a syntactically correct IPv4/IPv6 address; no network lookup occurs. |
| 45 | `time = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))` | Parses an ISO timestamp into an aware datetime; replacing Z supports Python 3.9 UTC input. |
| 46 | `if time.utcoffset() is None:` | Conditional: evaluate time.utcoffset() is None; execute the indented branch only when true. |
| 47 | `raise ValueError(f'Row {row_number}: timestamp needs a UTC offset')` | Rejects invalid input with a clear reason. This prevents silently treating malformed records as valid evidence. |
| 48 | `event['_time'] = time` | Assigns event['_time'] from the expression shown. Square-bracket access retrieves a dictionary value; literals and calls construct the configured value. |
| 49 | `return event` | Returns event to the caller; the function stops here. |
| 52 | `def load_events(path):` | Defines load_events as a reusable function; parameters supply inputs and the indented body runs when called. |
| 53 | `"""Fail closed on malformed input; no partial report is produced."""` | Docstring describing the module or current function; it documents behavior rather than running detection logic. |
| 54 | `path = Path(path)` | Assigns path from the expression shown. Square-bracket access retrieves a dictionary value; literals and calls construct the configured value. |
| 55 | `with path.open(encoding='utf-8', newline='') as handle:` | Context manager opens the file and reliably closes it when the indented block exits, including on errors. |
| 56 | `if path.suffix.lower() == '.csv':` | Conditional: evaluate path.suffix.lower() == '.csv'; execute the indented branch only when true. |
| 57 | `reader = csv.DictReader(handle)` | Reads CSV rows as dictionaries keyed by the header names. |
| 58 | `if not reader.fieldnames or len(set(reader.fieldnames)) != len(reader.fieldnames):` | Conditional: evaluate not reader.fieldnames or len(set(reader.fieldnames)) != len(reader.fieldnames); execute the indented branch only when true. |
| 59 | `raise ValueError('Missing or duplicate CSV header')` | Rejects invalid input with a clear reason. This prevents silently treating malformed records as valid evidence. |
| 60 | `raw = list(reader)` | Assigns raw from the expression shown. Square-bracket access retrieves a dictionary value; literals and calls construct the configured value. |
| 61 | `if any(None in row for row in raw):` | Conditional: evaluate any(None in row for row in raw); execute the indented branch only when true. |
| 62 | `raise ValueError('CSV row has excess columns')` | Rejects invalid input with a clear reason. This prevents silently treating malformed records as valid evidence. |
| 63 | `elif path.suffix.lower() == '.json':` | Conditional: evaluate path.suffix.lower() == '.json'; execute the indented branch only when true. |
| 64 | `raw = json.load(handle)` | Parses JSON text into Python dictionaries/lists; malformed JSON raises ValueError via JSONDecodeError. |
| 65 | `if not isinstance(raw, list):` | Conditional: evaluate not isinstance(raw, list); execute the indented branch only when true. |
| 66 | `raise ValueError('JSON input must be an array of event objects')` | Rejects invalid input with a clear reason. This prevents silently treating malformed records as valid evidence. |
| 67 | `else:` | Alternative branch used when the preceding condition is false. |
| 68 | `raise ValueError('Input must use .csv or .json')` | Rejects invalid input with a clear reason. This prevents silently treating malformed records as valid evidence. |
| 69 | `if not raw:` | Conditional: evaluate not raw; execute the indented branch only when true. |
| 70 | `raise ValueError('Input contains no events')` | Rejects invalid input with a clear reason. This prevents silently treating malformed records as valid evidence. |
| 71 | `events = [validate_record(row, i) for i, row in enumerate(raw, 2)]` | List/dictionary comprehension builds events by iterating and optionally filtering in one expression. |
| 72 | `ids = [event['EventRecordID'] for event in events]` | List/dictionary comprehension builds ids by iterating and optionally filtering in one expression. |
| 73 | `if len(ids) != len(set(ids)):` | Conditional: evaluate len(ids) != len(set(ids)); execute the indented branch only when true. |
| 74 | `raise ValueError('Duplicate lab EventRecordID')` | Rejects invalid input with a clear reason. This prevents silently treating malformed records as valid evidence. |
| 75 | `events.sort(key=lambda event: (event['_time'], event['EventRecordID']))` | Orders values deterministically; event ordering uses timestamp and lab record ID. |
| 76 | `LOG.info('Loaded and validated %d events', len(events))` | Logs operational status without printing account names, source IPs, credentials or finding contents. |
| 77 | `return events` | Returns events to the caller; the function stops here. |
| 80 | `def analyze(events, failure_threshold=10, spray_threshold=10, success_threshold=5):` | Defines analyze as a reusable function; parameters supply inputs and the indented body runs when called. |
| 81 | `"""Correlate rolling windows with dictionaries and bounded deques."""` | Docstring describing the module or current function; it documents behavior rather than running detection logic. |
| 82 | `if min(failure_threshold, spray_threshold, success_threshold) < 1:` | Conditional: evaluate min(failure_threshold, spray_threshold, success_threshold) < 1; execute the indented branch only when true. |
| 83 | `raise ValueError('Thresholds must be positive')` | Rejects invalid input with a clear reason. This prevents silently treating malformed records as valid evidence. |
| 84 | `failed_users = Counter()` | Creates a Counter dictionary for failed_users; it stores counts per identity/source or prior logons. |
| 85 | `failed_sources = Counter()` | Creates a Counter dictionary for failed_sources; it stores counts per identity/source or prior logons. |
| 86 | `failures = defaultdict(deque)` | Creates failures, a dictionary that automatically supplies a fresh deque for each unseen key. |
| 87 | `source_failures = defaultdict(deque)` | Creates source_failures, a dictionary that automatically supplies a fresh deque for each unseen key. |
| 88 | `account_history = Counter()` | Creates a Counter dictionary for account_history; it stores counts per identity/source or prior logons. |
| 89 | `seen_origins = set()` | Initializes an empty set for unique keys or known origins. |
| 90 | `findings = []` | Initializes an empty list for ordered results, appended as events are analyzed. |
| 91 | `emitted = set()` | Initializes an empty set for unique keys or known origins. |
| 93 | `def emit(rule, event, evidence, reason, severity='Medium'):` | Defines emit as a reusable function; parameters supply inputs and the indented body runs when called. |
| 94 | `# One row per rule and triggering event; repeated rolling candidates remain visible.` | Comment: One row per rule and triggering event; repeated rolling candidates remain visible. |
| 95 | `key = (rule, event['EventRecordID'])` | Assigns key from the expression shown. Square-bracket access retrieves a dictionary value; literals and calls construct the configured value. |
| 96 | `if key in emitted:` | Conditional: evaluate key in emitted; execute the indented branch only when true. |
| 97 | `return` | Continues the expression or call on the preceding line, supplying the displayed values, fields or function arguments. |
| 98 | `emitted.add(key)` | Adds a unique item to a set, used for deduplication or previously observed service origins. |
| 99 | `findings.append(dict(rule=rule, severity=severity, account=event['Account_Name'],` | Appends one item to a list or deque; candidate dictionaries and failure events retain their supporting data. |
| 100 | `source_ip=event['Source_Network_Address'], computer=event['ComputerName'],` | Assigns source_ip from the expression shown. Square-bracket access retrieves a dictionary value; literals and calls construct the configured value. |
| 101 | `timestamp=event['timestamp'],` | Continues the expression or call on the preceding line, supplying the displayed values, fields or function arguments. |
| 102 | `event_record_ids=sorted({e['EventRecordID'] for e in evidence}), reason=reason))` | Continues the expression or call on the preceding line, supplying the displayed values, fields or function arguments. |
| 104 | `for event in sorted(events, key=lambda e: (e['_time'], e['EventRecordID'])):` | Loop: event in sorted(events, key=lambda e: (e['_time'], e['EventRecordID'])). Each iteration processes one field, row, event, finding or count entry. |
| 105 | `time = event['_time']` | Assigns time from the expression shown. Square-bracket access retrieves a dictionary value; literals and calls construct the configured value. |
| 106 | `user = event['Account_Name']` | Assigns user from the expression shown. Square-bracket access retrieves a dictionary value; literals and calls construct the configured value. |
| 107 | `source = event['Source_Network_Address']` | Assigns source from the expression shown. Square-bracket access retrieves a dictionary value; literals and calls construct the configured value. |
| 108 | `key = (user, source, event['ComputerName'])` | Assigns key from the expression shown. Square-bracket access retrieves a dictionary value; literals and calls construct the configured value. |
| 109 | `recent = failures[key]` | Assigns recent from the expression shown. Square-bracket access retrieves a dictionary value; literals and calls construct the configured value. |
| 110 | `# Only failures in the last fifteen minutes are retained for this tuple.` | Comment: Only failures in the last fifteen minutes are retained for this tuple. |
| 111 | `while recent and time - recent[0]['_time'] > timedelta(minutes=15):` | Repeatedly remove expired history while recent and time - recent[0]['_time'] > timedelta(minutes=15). This keeps the active correlation window time-bounded. |
| 112 | `recent.popleft()` | Removes the oldest deque item after its event falls outside the rolling time window. |
| 113 | `code = event['EventCode']` | Assigns code from the expression shown. Square-bracket access retrieves a dictionary value; literals and calls construct the configured value. |
| 114 | `if code == 4625:` | Conditional: evaluate code == 4625; execute the indented branch only when true. |
| 115 | `failed_users[user] += 1` | Increments a dictionary/Counter value; a missing Counter key starts at zero. |
| 116 | `failed_sources[source] += 1` | Increments a dictionary/Counter value; a missing Counter key starts at zero. |
| 117 | `recent.append(event)` | Appends one item to a list or deque; candidate dictionaries and failure events retain their supporting data. |
| 118 | `burst = [e for e in recent if time - e['_time'] <= timedelta(minutes=10)]` | List/dictionary comprehension builds burst by iterating and optionally filtering in one expression. |
| 119 | `if len(burst) >= failure_threshold:` | Conditional: evaluate len(burst) >= failure_threshold; execute the indented branch only when true. |
| 120 | `emit('brute_force_candidate', event, burst, 'Repeated failures within ten minutes')` | Calls the nested candidate builder with a rule name, current trigger, evidence and analyst-review reason. |
| 121 | `breadth = source_failures[source]` | Assigns breadth from the expression shown. Square-bracket access retrieves a dictionary value; literals and calls construct the configured value. |
| 122 | `breadth.append(event)` | Appends one item to a list or deque; candidate dictionaries and failure events retain their supporting data. |
| 123 | `while breadth and time - breadth[0]['_time'] > timedelta(minutes=30):` | Repeatedly remove expired history while breadth and time - breadth[0]['_time'] > timedelta(minutes=30). This keeps the active correlation window time-bounded. |
| 124 | `breadth.popleft()` | Removes the oldest deque item after its event falls outside the rolling time window. |
| 125 | `if len({e['Account_Name'] for e in breadth}) >= spray_threshold:` | Conditional: evaluate len({e['Account_Name'] for e in breadth}) >= spray_threshold; execute the indented branch only when true. |
| 126 | `emit('password_spray_candidate', event, list(breadth), 'Multiple identities targeted within thirty minutes')` | Calls the nested candidate builder with a rule name, current trigger, evidence and analyst-review reason. |
| 127 | `elif code == 4624:` | Conditional: evaluate code == 4624; execute the indented branch only when true. |
| 128 | `prior = [e for e in recent if e['_time'] < time]` | List/dictionary comprehension builds prior by iterating and optionally filtering in one expression. |
| 129 | `if len(prior) >= success_threshold:` | Conditional: evaluate len(prior) >= success_threshold; execute the indented branch only when true. |
| 130 | `emit('failure_then_success', event, prior + [event],` | Calls the nested candidate builder with a rule name, current trigger, evidence and analyst-review reason. |
| 131 | `'Success after repeated failures on the same account/source/target', 'High')` | Continues the expression or call on the preceding line, supplying the displayed values, fields or function arguments. |
| 132 | `origin = (user, event['Workstation_Name'])` | Assigns origin from the expression shown. Square-bracket access retrieves a dictionary value; literals and calls construct the configured value. |
| 133 | `if user.startswith('svc_') and account_history[user] >= 3 and origin not in seen_origins:` | Conditional: evaluate user.startswith('svc_') and account_history[user] >= 3 and origin not in seen_origins; execute the indented branch only when true. |
| 134 | `emit('service_origin_novelty', event, [event],` | Calls the nested candidate builder with a rule name, current trigger, evidence and analyst-review reason. |
| 135 | `'New service origin after at least three prior account logons; verify baseline')` | Continues the expression or call on the preceding line, supplying the displayed values, fields or function arguments. |
| 136 | `account_history[user] += 1` | Increments a dictionary/Counter value; a missing Counter key starts at zero. |
| 137 | `seen_origins.add(origin)` | Adds a unique item to a set, used for deduplication or previously observed service origins. |
| 138 | `elif code == 4672:` | Conditional: evaluate code == 4672; execute the indented branch only when true. |
| 139 | `hour = time.hour  # Uses each input timestamp's offset; this lab is UTC-06:00.` | Assigns hour from the expression shown. Square-bracket access retrieves a dictionary value; literals and calls construct the configured value. |
| 140 | `prior = [e for e in recent if e['_time'] < time]` | List/dictionary comprehension builds prior by iterating and optionally filtering in one expression. |
| 141 | `if len(prior) >= 3 or hour < 8 or hour >= 18:` | Conditional: evaluate len(prior) >= 3 or hour < 8 or hour >= 18; execute the indented branch only when true. |
| 142 | `emit('privileged_context_review', event, prior + [event],` | Calls the nested candidate builder with a rule name, current trigger, evidence and analyst-review reason. |
| 143 | `'Privileged session with recent failures or outside office hours', 'High')` | Continues the expression or call on the preceding line, supplying the displayed values, fields or function arguments. |
| 144 | `return dict(schema_version=1, interpretation='Candidates for analyst review; not confirmed incidents',` | Returns dict(schema_version=1, interpretation='Candidates for analyst review; not confirmed incidents', to the caller; the function stops here. |
| 145 | `event_count=len(events), failed_logins_by_user=dict(sorted(failed_users.items())),` | Orders values deterministically; event ordering uses timestamp and lab record ID. |
| 146 | `failed_logins_by_source_ip=dict(sorted(failed_sources.items())),` | Continues the expression or call on the preceding line, supplying the displayed values, fields or function arguments. |
| 147 | `thresholds=dict(brute_force_10m=failure_threshold, spray_accounts_30m=spray_threshold,` | Continues the expression or call on the preceding line, supplying the displayed values, fields or function arguments. |
| 148 | `failures_before_success_15m=success_threshold),` | Continues the expression or call on the preceding line, supplying the displayed values, fields or function arguments. |
| 149 | `findings=findings)` | Continues the expression or call on the preceding line, supplying the displayed values, fields or function arguments. |
| 152 | `def export_summary(summary, output_dir):` | Defines export_summary as a reusable function; parameters supply inputs and the indented body runs when called. |
| 153 | `"""Write detailed candidates and count summaries in portable formats."""` | Docstring describing the module or current function; it documents behavior rather than running detection logic. |
| 154 | `folder = Path(output_dir)` | Assigns folder from the expression shown. Square-bracket access retrieves a dictionary value; literals and calls construct the configured value. |
| 155 | `folder.mkdir(parents=True, exist_ok=True)` | Creates the output directory and missing parents; exist_ok permits an already existing directory. |
| 156 | `(folder / 'investigation_summary.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')` | Writes a UTF-8 text file; JSON is serialized with json.dumps for structured, portable output. |
| 157 | `with (folder / 'investigation_findings.csv').open('w', encoding='utf-8', newline='') as handle:` | Context manager opens the file and reliably closes it when the indented block exits, including on errors. |
| 158 | `writer = csv.DictWriter(handle, fieldnames=FINDING_FIELDS)` | Creates a CSV writer with explicit column ordering. |
| 159 | `writer.writeheader()` | Writes the CSV field-name header once before output rows. |
| 160 | `for finding in summary['findings']:` | Loop: finding in summary['findings']. Each iteration processes one field, row, event, finding or count entry. |
| 161 | `row = dict(finding)` | Assigns row from the expression shown. Square-bracket access retrieves a dictionary value; literals and calls construct the configured value. |
| 162 | `row['event_record_ids'] = ';'.join(map(str, row['event_record_ids']))` | Assigns row['event_record_ids'] from the expression shown. Square-bracket access retrieves a dictionary value; literals and calls construct the configured value. |
| 163 | `writer.writerow(row)` | Serializes one row with CSV quoting, rather than manually concatenating potentially unsafe delimiters. |
| 164 | `with (folder / 'failure_counts.csv').open('w', encoding='utf-8', newline='') as handle:` | Context manager opens the file and reliably closes it when the indented block exits, including on errors. |
| 165 | `writer = csv.writer(handle)` | Creates a CSV writer for simple positional count-summary rows. |
| 166 | `writer.writerow(['dimension', 'value', 'failures'])` | Serializes one row with CSV quoting, rather than manually concatenating potentially unsafe delimiters. |
| 167 | `for dimension, counts in [('account', summary['failed_logins_by_user']),` | Loop: dimension, counts in [('account', summary['failed_logins_by_user']),. Each iteration processes one field, row, event, finding or count entry. |
| 168 | `('source_ip', summary['failed_logins_by_source_ip'])]:` | Continues the expression or call on the preceding line, supplying the displayed values, fields or function arguments. |
| 169 | `for value, count in counts.items():` | Loop: value, count in counts.items(). Each iteration processes one field, row, event, finding or count entry. |
| 170 | `writer.writerow([dimension, value, count])` | Serializes one row with CSV quoting, rather than manually concatenating potentially unsafe delimiters. |
| 171 | `LOG.info('Exported summaries; review output privately')` | Logs operational status without printing account names, source IPs, credentials or finding contents. |
| 174 | `def main(argv=None):` | Defines main as a reusable function; parameters supply inputs and the indented body runs when called. |
| 175 | `parser = argparse.ArgumentParser(description=__doc__)` | Assigns parser from the expression shown. Square-bracket access retrieves a dictionary value; literals and calls construct the configured value. |
| 176 | `parser.add_argument('input', type=Path)` | Declares a command-line option or input path, including conversion/default/requirement settings shown in the code. |
| 177 | `parser.add_argument('--output-dir', type=Path, default=Path('reports/local_analysis'))` | Declares a command-line option or input path, including conversion/default/requirement settings shown in the code. |
| 178 | `parser.add_argument('--failure-threshold', type=int, default=10)` | Declares a command-line option or input path, including conversion/default/requirement settings shown in the code. |
| 179 | `parser.add_argument('--spray-threshold', type=int, default=10)` | Declares a command-line option or input path, including conversion/default/requirement settings shown in the code. |
| 180 | `parser.add_argument('--success-threshold', type=int, default=5)` | Declares a command-line option or input path, including conversion/default/requirement settings shown in the code. |
| 181 | `args = parser.parse_args(argv)` | Assigns args from the expression shown. Square-bracket access retrieves a dictionary value; literals and calls construct the configured value. |
| 182 | `logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')` | Configures INFO-level console logging and a simple severity/message format. |
| 183 | `try:` | Starts protected execution of input loading, analysis and export. Expected failures are handled by the following except block. |
| 184 | `events = load_events(args.input)` | Assigns events from the expression shown. Square-bracket access retrieves a dictionary value; literals and calls construct the configured value. |
| 185 | `summary = analyze(events, args.failure_threshold, args.spray_threshold, args.success_threshold)` | Assigns summary from the expression shown. Square-bracket access retrieves a dictionary value; literals and calls construct the configured value. |
| 186 | `export_summary(summary, args.output_dir)` | Continues the expression or call on the preceding line, supplying the displayed values, fields or function arguments. |
| 187 | `except (OSError, ValueError, TypeError, csv.Error) as error:` | Catches the listed input, parsing and file errors; returns a failed exit status instead of printing event contents. |
| 188 | `LOG.error('Analysis failed (%s). Check input schema, values, and file permissions.', type(error).__name__)` | Logs operational status without printing account names, source IPs, credentials or finding contents. |
| 189 | `return 1` | Returns 1 to the caller; the function stops here. |
| 190 | `return 0` | Returns 0 to the caller; the function stops here. |
| 193 | `if __name__ == '__main__':` | Runs the command-line entry point only when launched as a script; importing it in tests does not run main. |
| 194 | `raise SystemExit(main())` | Converts main’s return value to the operating-system exit code: zero succeeds, nonzero fails. |

## Practice without spoilers
1. Predict the example fixture’s two failure counts and explain why it is below default thresholds.
2. In a separate fixture, change one account name; predict dictionary keys before running the analyzer.
3. Explain why five failures after a success must not count as preceding failures. Find the unit test for reverse/equal timestamps.
4. Explain why an offset-free timestamp fails validation, and why Counter helps with a username seen for the first time.
5. Trace one fixture through load, validation, analyze and export; locate the list of dictionaries in the JSON output.

Do not claim understanding merely because tests pass. Change a harmless fixture, predict the outcome and compare it with what the functions actually do. Line numbers should be regenerated if you edit the source.
