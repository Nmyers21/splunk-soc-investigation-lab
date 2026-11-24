#!/usr/bin/env python3
"""Offline authentication triage. Produces leads, never compromise verdicts."""
import argparse
import csv
import ipaddress
import json
import logging
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path

LOG = logging.getLogger(__name__)
REQUIRED = ('timestamp EventCode Account_Name Source_Network_Address ComputerName '
            'Logon_Type Authentication_Package Workstation_Name Status Failure_Reason '
            'Department Source_Country EventRecordID').split()
STATUS = {4624: 'Success', 4625: 'Failure', 4634: 'Logoff',
          4648: 'Explicit credentials attempted', 4672: 'Special privileges assigned'}
FINDING_FIELDS = ['rule', 'severity', 'account', 'source_ip', 'computer',
                  'timestamp', 'event_record_ids', 'reason']


def validate_record(raw, row_number):
    """Copy and normalize one record without modifying the caller's data."""
    if not isinstance(raw, dict) or any(field not in raw for field in REQUIRED):
        raise ValueError(f'Row {row_number}: required fields missing')
    event = {field: raw[field] for field in REQUIRED}
    if any(value is None or isinstance(value, (dict, list, bool)) for value in event.values()):
        raise ValueError(f'Row {row_number}: unsupported field value')
    for field in REQUIRED:
        event[field] = str(event[field]).strip()
    for field in ['EventCode', 'Logon_Type', 'EventRecordID']:
        event[field] = int(event[field])
    code = event['EventCode']
    if code not in STATUS or event['Status'] != STATUS[code]:
        raise ValueError(f'Row {row_number}: inconsistent event status')
    if bool(event['Failure_Reason']) != (code == 4625):
        raise ValueError(f'Row {row_number}: inconsistent failure reason')
    if event['Authentication_Package'] not in ('NTLM', 'Kerberos'):
        raise ValueError(f'Row {row_number}: unsupported authentication package')
    if not 0 <= event['Logon_Type'] <= 13 or event['EventRecordID'] <= 0:
        raise ValueError(f'Row {row_number}: invalid numeric value')
    if any(not event[f] for f in ['Account_Name', 'ComputerName', 'Workstation_Name', 'Department', 'Source_Country']):
        raise ValueError(f'Row {row_number}: empty identity or context')
    ipaddress.ip_address(event['Source_Network_Address'])
    time = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
    if time.utcoffset() is None:
        raise ValueError(f'Row {row_number}: timestamp needs a UTC offset')
    event['_time'] = time
    return event


def load_events(path):
    """Fail closed on malformed input; no partial report is produced."""
    path = Path(path)
    with path.open(encoding='utf-8', newline='') as handle:
        if path.suffix.lower() == '.csv':
            reader = csv.DictReader(handle)
            if not reader.fieldnames or len(set(reader.fieldnames)) != len(reader.fieldnames):
                raise ValueError('Missing or duplicate CSV header')
            raw = list(reader)
            if any(None in row for row in raw):
                raise ValueError('CSV row has excess columns')
        elif path.suffix.lower() == '.json':
            raw = json.load(handle)
            if not isinstance(raw, list):
                raise ValueError('JSON input must be an array of event objects')
        else:
            raise ValueError('Input must use .csv or .json')
    if not raw:
        raise ValueError('Input contains no events')
    events = [validate_record(row, i) for i, row in enumerate(raw, 2)]
    ids = [event['EventRecordID'] for event in events]
    if len(ids) != len(set(ids)):
        raise ValueError('Duplicate lab EventRecordID')
    events.sort(key=lambda event: (event['_time'], event['EventRecordID']))
    LOG.info('Loaded and validated %d events', len(events))
    return events


def analyze(events, failure_threshold=10, spray_threshold=10, success_threshold=5):
    """Correlate rolling windows with dictionaries and bounded deques."""
    if min(failure_threshold, spray_threshold, success_threshold) < 1:
        raise ValueError('Thresholds must be positive')
    failed_users = Counter()
    failed_sources = Counter()
    failures = defaultdict(deque)
    source_failures = defaultdict(deque)
    account_history = Counter()
    seen_origins = set()
    findings = []
    emitted = set()

    def emit(rule, event, evidence, reason, severity='Medium'):
        # One row per rule and triggering event; repeated rolling candidates remain visible.
        key = (rule, event['EventRecordID'])
        if key in emitted:
            return
        emitted.add(key)
        findings.append(dict(rule=rule, severity=severity, account=event['Account_Name'],
            source_ip=event['Source_Network_Address'], computer=event['ComputerName'],
            timestamp=event['timestamp'],
            event_record_ids=sorted({e['EventRecordID'] for e in evidence}), reason=reason))

    for event in sorted(events, key=lambda e: (e['_time'], e['EventRecordID'])):
        time = event['_time']
        user = event['Account_Name']
        source = event['Source_Network_Address']
        key = (user, source, event['ComputerName'])
        recent = failures[key]
        # Only failures in the last fifteen minutes are retained for this tuple.
        while recent and time - recent[0]['_time'] > timedelta(minutes=15):
            recent.popleft()
        code = event['EventCode']
        if code == 4625:
            failed_users[user] += 1
            failed_sources[source] += 1
            recent.append(event)
            burst = [e for e in recent if time - e['_time'] <= timedelta(minutes=10)]
            if len(burst) >= failure_threshold:
                emit('brute_force_candidate', event, burst, 'Repeated failures within ten minutes')
            breadth = source_failures[source]
            breadth.append(event)
            while breadth and time - breadth[0]['_time'] > timedelta(minutes=30):
                breadth.popleft()
            if len({e['Account_Name'] for e in breadth}) >= spray_threshold:
                emit('password_spray_candidate', event, list(breadth), 'Multiple identities targeted within thirty minutes')
        elif code == 4624:
            prior = [e for e in recent if e['_time'] < time]
            if len(prior) >= success_threshold:
                emit('failure_then_success', event, prior + [event],
                     'Success after repeated failures on the same account/source/target', 'High')
            origin = (user, event['Workstation_Name'])
            if user.startswith('svc_') and account_history[user] >= 3 and origin not in seen_origins:
                emit('service_origin_novelty', event, [event],
                     'New service origin after at least three prior account logons; verify baseline')
            account_history[user] += 1
            seen_origins.add(origin)
        elif code == 4672:
            hour = time.hour  # Uses each input timestamp's offset; this lab is UTC-06:00.
            prior = [e for e in recent if e['_time'] < time]
            if len(prior) >= 3 or hour < 8 or hour >= 18:
                emit('privileged_context_review', event, prior + [event],
                     'Privileged session with recent failures or outside office hours', 'High')
    return dict(schema_version=1, interpretation='Candidates for analyst review; not confirmed incidents',
                event_count=len(events), failed_logins_by_user=dict(sorted(failed_users.items())),
                failed_logins_by_source_ip=dict(sorted(failed_sources.items())),
                thresholds=dict(brute_force_10m=failure_threshold, spray_accounts_30m=spray_threshold,
                                failures_before_success_15m=success_threshold),
                findings=findings)


def export_summary(summary, output_dir):
    """Write detailed candidates and count summaries in portable formats."""
    folder = Path(output_dir)
    folder.mkdir(parents=True, exist_ok=True)
    (folder / 'investigation_summary.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
    with (folder / 'investigation_findings.csv').open('w', encoding='utf-8', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=FINDING_FIELDS)
        writer.writeheader()
        for finding in summary['findings']:
            row = dict(finding)
            row['event_record_ids'] = ';'.join(map(str, row['event_record_ids']))
            writer.writerow(row)
    with (folder / 'failure_counts.csv').open('w', encoding='utf-8', newline='') as handle:
        writer = csv.writer(handle)
        writer.writerow(['dimension', 'value', 'failures'])
        for dimension, counts in [('account', summary['failed_logins_by_user']),
                                  ('source_ip', summary['failed_logins_by_source_ip'])]:
            for value, count in counts.items():
                writer.writerow([dimension, value, count])
    LOG.info('Exported summaries; review output privately')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path)
    parser.add_argument('--output-dir', type=Path, default=Path('reports/local_analysis'))
    parser.add_argument('--failure-threshold', type=int, default=10)
    parser.add_argument('--spray-threshold', type=int, default=10)
    parser.add_argument('--success-threshold', type=int, default=5)
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
    try:
        events = load_events(args.input)
        summary = analyze(events, args.failure_threshold, args.spray_threshold, args.success_threshold)
        export_summary(summary, args.output_dir)
    except (OSError, ValueError, TypeError, csv.Error) as error:
        LOG.error('Analysis failed (%s). Check input schema, values, and file permissions.', type(error).__name__)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
