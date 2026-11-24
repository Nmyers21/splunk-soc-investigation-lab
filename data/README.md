# Data
The original, canonical dataset remains at `../soc_authentication_logs.csv` to preserve existing import paths. Do not regenerate it. This directory accepts optional JSON/CSV exports and fixtures; exports are ignored by Git by default.

`example_events.json` is a tiny unrelated automation demonstration, not evidence from the blind dataset. Splunk API exports may contain search-result rows rather than full authentication records; use a raw-event search selecting all thirteen required fields when feeding the analyzer.
