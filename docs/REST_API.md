# Optional read-only Splunk REST integration
The client has not been executed against your Splunk instance. Do not run it until you choose to authorize access. It makes GET requests only to `/services/search/jobs/{sid}/results`; it neither submits searches nor changes Splunk configuration. Run your search manually in Splunk, wait for completion, and obtain its SID from the job inspector. The job must still exist and be accessible to the API identity.

Environment settings:

| Variable | Purpose |
| --- | --- |
| SPLUNK_HOST | DNS hostname or IPv4 address, without scheme/path; defaults to localhost |
| SPLUNK_PORT | HTTPS management port; defaults to 8089, distinct from Splunk Web's port |
| SPLUNK_TOKEN | Bearer authentication token; preferred when supported and enabled |
| SPLUNK_USERNAME / SPLUNK_PASSWORD | Alternative Basic credentials, sent over verified HTTPS |
| SPLUNK_CA_FILE | Optional trusted CA PEM file for a lab/private CA |

Set credentials in your shell's environment securely. Do not put real credentials in source, shell history, screenshots or committed `.env` files. Token configuration, management-port access and role permissions are manual administrative steps.

After explicitly authorizing the connection, from the project root:

```sh
python3 scripts/splunk_api.py --search-id YOUR_COMPLETED_JOB_SID --output data/splunk_results.json --timeout 30
```

TLS verification is always enabled; there is no insecure bypass option. A self-signed lab certificate needs a trusted CA/certificate chain and a matching hostname. Redirects are denied so authorization headers cannot be forwarded elsewhere. HTTP 401/403, timeouts, network/TLS errors, wrong content types, invalid JSON, search errors, missing completion status and preview results fail the request. Pagination preserves result order, has a row cap and fails explicitly rather than silently truncating. No credentials or response bodies are logged.

Use a dedicated least-privilege role with search capability and access to `soc_lab`; the API identity must be permitted to read the existing job under its ownership/sharing rules. Administrative capabilities are not needed for this client. Do not grant broad access to all indexes merely to bypass a 403. Reading another user's private SID will fail even when index permissions exist. Consult the administrator for token enablement and role restrictions.

To feed the analyzer, manually execute a raw-event search selecting all original fields, not an aggregated `stats` query. Exported REST values may be strings; the analyzer normalizes numeric fields. The fixture tests mock all network behavior. GET reads may expose sensitive events: keep exports private.

References: [Splunk search endpoints](https://help.splunk.com/en/splunk-enterprise/leverage-rest-apis/rest-api-reference/10.6/search-endpoints/search-endpoint-descriptions), [exporting search results](https://help.splunk.com/en/splunk-enterprise/search/search-manual/9.0/export-search-results/export-data-using-the-splunk-rest-api).
