# isc-feeds

Pulls the Internet Storm Center feeds, collapses them into IPv4 CIDRs, and writes them to the repo-root [`feeds/`](../feeds/). The [Update Feeds](../.github/workflows/update-feeds.yml) workflow runs this every day.

## Running Locally

```bash
just generate
```

## Development

Linting, formatting, and typing follow the Google Python Style Guide via ruff and ty.

```bash
just format   # apply formatting and safe lint fixes
just check    # what CI runs: format check, lint, type check, tests
just upgrade  # upgrade locked dependencies
```
