# isc-threat-feeds
Parses feeds from the Internet Storm Center into IPv4 CIDR lists for consumption by other tools/processes.

A GitHub Action refreshes the lists daily and commits them to [`feeds/`](feeds/). Available lists:
* https://raw.githubusercontent.com/edepree/isc-threat-feeds/master/feeds/bots.txt
* https://raw.githubusercontent.com/edepree/isc-threat-feeds/master/feeds/malware.txt
* https://raw.githubusercontent.com/edepree/isc-threat-feeds/master/feeds/research.txt
* https://raw.githubusercontent.com/edepree/isc-threat-feeds/master/feeds/alltor.txt
* https://raw.githubusercontent.com/edepree/isc-threat-feeds/master/feeds/torexit.txt

## Running Locally

```bash
uv run isc_threat_feeds.py
```

## Development

Linting, formatting, and typing follow the Google Python Style Guide via ruff and ty. CI runs:

```bash
uv run ruff format --check .
uv run ruff check .
uv run ty check
uv run pytest
```
