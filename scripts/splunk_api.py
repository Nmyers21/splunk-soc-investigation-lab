#!/usr/bin/env python3
"""Read completed Splunk search results using GET only; never submits searches."""
import argparse
import base64
import json
import logging
import os
import ssl
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, build_opener, HTTPSHandler, HTTPRedirectHandler

LOG = logging.getLogger(__name__)


class NoRedirect(HTTPRedirectHandler):
    """Do not forward credentials to redirected hosts."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def get_payload(opener, url, authorization, timeout):
    request = Request(url, headers={'Authorization': authorization, 'Accept': 'application/json'}, method='GET')
    try:
        with opener.open(request, timeout=timeout) as response:
            if response.status != 200:
                raise ValueError('Unexpected HTTP status')
            if response.headers.get_content_type() != 'application/json':
                raise ValueError('Expected application/json response')
            content = response.read(10_000_001)
            if len(content) > 10_000_000:
                raise ValueError('Response exceeds safe page-size limit')
            payload = json.loads(content)
    except HTTPError as error:
        error.close()  # Release response resources before reporting a sanitized error.
        if error.code in (401, 403):
            raise ValueError('Authentication failed or search/index permissions are insufficient') from None
        raise ValueError(f'Splunk HTTP error {error.code}') from None
    except (URLError, TimeoutError, OSError):
        raise ValueError('Connection, TLS, or timeout error; verify host, CA trust and connectivity') from None
    if not isinstance(payload, dict):
        raise ValueError('Malformed JSON envelope')
    return payload


def check_job_done(opener, endpoint, authorization, timeout):
    payload = get_payload(opener, endpoint + '?output_mode=json', authorization, timeout)
    entries = payload.get('entry')
    if not isinstance(entries, list) or len(entries) != 1 or not isinstance(entries[0], dict):
        raise ValueError('Malformed job status')
    content = entries[0].get('content')
    if not isinstance(content, dict) or content.get('isDone') not in (True, 1, '1'):
        raise ValueError('Search job has not finished')
    if content.get('isFailed') in (True, 1, '1') or content.get('dispatchState') != 'DONE':
        raise ValueError('Search job failed or did not complete normally')


def get_page(opener, url, authorization, timeout):
    payload = get_payload(opener, url, authorization, timeout)
    if not isinstance(payload.get('results'), list):
        raise ValueError('Malformed JSON result envelope')
    if payload.get('preview') not in (False, 0, '0', 'false'):
        raise ValueError('Search is not complete, or completion status is missing')
    if any(not isinstance(row, dict) for row in payload['results']):
        raise ValueError('Expected result objects')
    messages = payload.get('messages', [])
    if not isinstance(messages, list) or any(not isinstance(m, dict) for m in messages):
        raise ValueError('Malformed API messages')
    if any(m.get('type') in ('ERROR', 'FATAL') for m in messages):
        raise ValueError('Splunk reported a search error')
    return payload['results']


def fetch_results(search_id, page_size=500, timeout=30, max_rows=100000, opener=None):
    if not search_id or min(page_size, timeout, max_rows) <= 0:
        raise ValueError('Search ID and positive limits are required')
    host = os.environ.get('SPLUNK_HOST', 'localhost')
    port = int(os.environ.get('SPLUNK_PORT', '8089'))
    if not host or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-' for c in host):
        raise ValueError('SPLUNK_HOST must be a DNS hostname or IPv4 address without a scheme')
    if not 1 <= port <= 65535:
        raise ValueError('Invalid management port')
    token = os.environ.get('SPLUNK_TOKEN')
    if token:
        authorization = 'Bearer ' + token
    else:
        user, password = os.environ.get('SPLUNK_USERNAME'), os.environ.get('SPLUNK_PASSWORD')
        if not user or not password:
            raise ValueError('Set SPLUNK_TOKEN or both SPLUNK_USERNAME and SPLUNK_PASSWORD')
        credentials = base64.b64encode(f'{user}:{password}'.encode()).decode()
        authorization = 'Basic ' + credentials
    context = ssl.create_default_context(cafile=os.environ.get('SPLUNK_CA_FILE') or None)
    if opener is None:
        opener = build_opener(HTTPSHandler(context=context), NoRedirect())
    job_endpoint = f'https://{host}:{port}/services/search/jobs/{quote(search_id, safe="")}'
    check_job_done(opener, job_endpoint, authorization, timeout)
    endpoint = job_endpoint + '/results'
    rows = []
    while True:
        # Fetch one extra row at the cap so truncation cannot silently look complete.
        count = min(page_size, max_rows - len(rows) + 1)
        params = urlencode(dict(output_mode='json', count=count, offset=len(rows)))
        page = get_page(opener, endpoint + '?' + params, authorization, timeout)
        if len(page) > count:
            raise ValueError('Server returned more rows than requested')
        rows.extend(page)
        if len(rows) > max_rows:
            raise ValueError('Result limit exceeded; narrow the completed search')
        if len(page) < count:
            break
    return rows


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--search-id', required=True)
    parser.add_argument('--output', type=Path, default=Path('data/splunk_results.json'))
    parser.add_argument('--timeout', type=int, default=30)
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
    try:
        rows = fetch_results(args.search_id, timeout=args.timeout)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(rows, indent=2) + '\n', encoding='utf-8')
        LOG.info('Saved %d result rows', len(rows))
    except (OSError, ValueError, TypeError):
        LOG.error('Retrieval failed. Check credentials, permissions, completed SID, TLS trust, and API response.')
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
