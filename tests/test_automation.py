"""Independent fictional fixtures: never read the blind dataset or answer key."""
import csv
import io
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from email.message import Message

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import analyze_auth as auth
import splunk_api as api


def raw_event(number=1, code=4625, seconds=0, user='test.user', origin='TEST-PC'):
    return dict(zip(auth.REQUIRED, [
        (datetime(2026, 1, 1, 12, tzinfo=timezone.utc)+timedelta(seconds=seconds)).isoformat(),
        code, user, '192.0.2.10', 'TEST-SERVER', 3, 'NTLM', origin,
        auth.STATUS[code], 'Bad password' if code==4625 else '', 'Test', 'United States', number]))


def normalized(*rows):
    return [auth.validate_record(row, i) for i,row in enumerate(rows, 1)]


class AnalyzerTests(unittest.TestCase):
    def test_csv_json_roundtrip_exports_and_counting(self):
        raw=[raw_event(i+1,seconds=i*20) for i in range(5)]
        raw.append(raw_event(6,4624,120))
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/'input.json').write_text(json.dumps(raw))
            with (root/'input.csv').open('w',newline='') as handle:
                writer=csv.DictWriter(handle,fieldnames=auth.REQUIRED)
                writer.writeheader();writer.writerows(raw)
            events=auth.load_events(root/'input.csv')
            self.assertEqual(events,auth.load_events(root/'input.json'))
            summary=auth.analyze(events)
            self.assertEqual(summary['failed_logins_by_user'],{'test.user':5})
            self.assertEqual(summary['failed_logins_by_source_ip'],{'192.0.2.10':5})
            self.assertEqual([f['rule'] for f in summary['findings']],['failure_then_success'])
            self.assertEqual(summary['findings'][0]['event_record_ids'],[1,2,3,4,5,6])
            auth.export_summary(summary,root/'output')
            self.assertEqual(json.loads((root/'output/investigation_summary.json').read_text()),summary)
            with (root/'output/investigation_findings.csv').open() as handle:
                self.assertEqual(len(list(csv.DictReader(handle))),1)
            self.assertTrue((root/'output/failure_counts.csv').is_file())

    def test_rolling_window_boundary_and_separate_targets(self):
        rows=[raw_event(i+1,seconds=i) for i in range(5)]
        rows += [raw_event(6,4624,905),raw_event(7,4624,6)]
        rows[-1]['ComputerName']='OTHER-SERVER'
        self.assertFalse(auth.analyze(normalized(*rows))['findings'])

    def test_no_reverse_or_equal_time_correlation(self):
        rows=[raw_event(i+1,seconds=60) for i in range(5)]
        for sec in [0,60]:
            summary=auth.analyze(normalized(*rows,raw_event(9,4624,sec)))
            self.assertFalse(any(f['rule']=='failure_then_success' for f in summary['findings']))

    def test_burst_and_spray(self):
        rows=[raw_event(i+1,seconds=i) for i in range(10)]
        result=auth.analyze(normalized(*rows))
        self.assertIn('brute_force_candidate',[f['rule'] for f in result['findings']])
        rows=[raw_event(i+1,seconds=i,user=f'test.{i}') for i in range(10)]
        self.assertIn('password_spray_candidate',[f['rule'] for f in auth.analyze(normalized(*rows))['findings']])

    def test_service_new_origin_and_privilege(self):
        rows=[raw_event(i+1,4624,i,user='svc_test') for i in range(3)]
        rows += [raw_event(4,4624,5,user='svc_test',origin='OTHER-PC')]
        result=auth.analyze(normalized(*rows))
        self.assertEqual(result['findings'][0]['rule'],'service_origin_novelty')
        p=raw_event(5,4672); p['timestamp']='2026-01-01T03:00:00+00:00'
        self.assertEqual(auth.analyze(normalized(p))['findings'][0]['rule'],'privileged_context_review')

    def test_malformed_records(self):
        variants=[{'Status':'Success'},{'timestamp':'2026-01-01T12:00:00'},
                  {'Source_Network_Address':'bad-ip'}, {'Authentication_Package':'bad'},
                  {'Failure_Reason':''},{'EventCode':999},{'Account_Name':''}, {'Logon_Type':-1}]
        for changes in variants:
            with self.subTest(changes=changes),self.assertRaises(ValueError):
                auth.validate_record(dict(raw_event(),**changes),1)

    def test_duplicate_ids_bad_json_and_cli_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            file=Path(tmp)/'input.json'
            for value in [[raw_event(),raw_event()],{},[],['bad']]:
                file.write_text(json.dumps(value))
                with self.assertRaises(ValueError): auth.load_events(file)
            self.assertEqual(auth.main([str(Path(tmp)/'missing.csv')]),1)

    def test_bad_csv_extra_columns_and_thresholds(self):
        with tempfile.TemporaryDirectory() as tmp:
            file=Path(tmp)/'bad.csv';file.write_text('a,a\n1,2\n')
            with self.assertRaises(ValueError):auth.load_events(file)
            file.write_text('a\n1,2\n')
            with self.assertRaises(ValueError):auth.load_events(file)
        with self.assertRaises(ValueError):auth.analyze([],failure_threshold=0)


class Response:
    status=200
    def __init__(self,payload,ctype='application/json'):
        self.payload=payload
        self.headers=Message();self.headers['Content-Type']=ctype
    def __enter__(self):return self
    def __exit__(self,*args):pass
    def read(self,limit):return self.payload[:limit]


class FakeOpener:
    def __init__(self,responses):self.responses=iter(responses);self.requests=[]
    def open(self,request,timeout):
        self.requests.append(request)
        response=next(self.responses)
        if isinstance(response,Exception):raise response
        return response


def response(rows,**kwargs):
    return Response(json.dumps(dict(results=rows,preview=False,**kwargs)).encode())


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.env=patch.dict(os.environ,{'SPLUNK_TOKEN':'test-token','SPLUNK_HOST':'localhost','SPLUNK_PORT':'8089'},clear=True)
        self.env.start();self.addCleanup(self.env.stop)
        self.job_check=patch.object(api,'check_job_done')
        self.job_check.start();self.addCleanup(self.job_check.stop)

    def test_completed_job_status(self):
        self.job_check.stop()
        for content,valid in [({'isDone':True,'isFailed':False,'dispatchState':'DONE'},True),
                              ({'isDone':False,'dispatchState':'RUNNING'},False),
                              ({'isDone':True,'isFailed':True,'dispatchState':'DONE'},False),
                              ({'isDone':True,'dispatchState':'FAILED'},False)]:
            opener=FakeOpener([Response(json.dumps({'entry':[{'content':content}]}).encode())])
            if valid:
                api.check_job_done(opener,'https://localhost/job','Bearer test',30)
            else:
                with self.assertRaises(ValueError):
                    api.check_job_done(opener,'https://localhost/job','Bearer test',30)

    def test_get_only_pagination_and_escaping(self):
        opener=FakeOpener([response([{'x':1},{'x':2}]),response([{'x':3}])])
        result=api.fetch_results('test/sid',page_size=2,opener=opener)
        self.assertEqual(len(result),3)
        self.assertTrue(all(r.get_method()=='GET' for r in opener.requests))
        self.assertIn('test%2Fsid',opener.requests[0].full_url)
        self.assertIn('offset=2',opener.requests[1].full_url)
        self.assertEqual(opener.requests[0].get_header('Authorization'),'Bearer test-token')

    def test_auth_and_connection_failures(self):
        for error in [HTTPError('test',401,'',{},None),HTTPError('test',403,'',{},None),
                      HTTPError('test',500,'',{},None),URLError('unreachable'),TimeoutError()]:
            with self.subTest(error=type(error).__name__),self.assertRaises(ValueError):
                api.fetch_results('sid',opener=FakeOpener([error]))

    def test_response_validation(self):
        bad=[Response(b'not json'),Response(b'{}'),Response(b'[]'),
             Response(b'{"results":[],"preview":true}'),Response(b'{"results":[]}'),
             Response(b'{"results":[1],"preview":false}'),Response(b'{}','text/html'),
             response([],messages=[{'type':'ERROR'}])]
        for item in bad:
            with self.subTest(item=item),self.assertRaises(ValueError):
                api.fetch_results('sid',opener=FakeOpener([item]))

    def test_result_cap_and_config_validation(self):
        with self.assertRaises(ValueError):
            api.fetch_results('sid',max_rows=1,opener=FakeOpener([response([{},{}])]))
        os.environ['SPLUNK_HOST']='https://bad'
        with self.assertRaises(ValueError):api.fetch_results('sid',opener=FakeOpener([]))
        os.environ['SPLUNK_HOST']='localhost';os.environ.pop('SPLUNK_TOKEN')
        with self.assertRaises(ValueError):api.fetch_results('sid',opener=FakeOpener([]))

    def test_redirect_denied_and_basic_auth(self):
        self.assertIsNone(api.NoRedirect().redirect_request(None,None,302,'',{},'https://example.com'))
        os.environ.pop('SPLUNK_TOKEN');os.environ['SPLUNK_USERNAME']='test';os.environ['SPLUNK_PASSWORD']='secret'
        opener=FakeOpener([response([])])
        api.fetch_results('sid',opener=opener)
        self.assertTrue(opener.requests[0].get_header('Authorization').startswith('Basic '))


if __name__=='__main__':unittest.main()
