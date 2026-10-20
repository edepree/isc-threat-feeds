# isc-unifi-connector

UniFi Network has no way to subscribe to a dynamic IP list. This container closes that gap. Each run downloads the [ISC threat feeds](../README.md) you enable and syncs each one into a UniFi traffic matching list named `isc-<feed>`. It runs once and exits, so schedule it with a Kubernetes `CronJob`, cron, or similar. The feeds refresh daily at about 06:17 UTC.

The connector only creates and updates lists named `isc-*`. It never touches firewall policies or any other list.

## Setup

1. Create an API key in UniFi Network under *Settings → Control Plane → Integrations* or use a cloud key from [unifi.ui.com](https://unifi.ui.com) if you connect through the cloud connector.
2. Run the container once to create / update the list(s). Put the key in an env file so it stays out of shell history:

   ```bash
   cat > unifi.env <<'ENV'
   UNIFI_URL=https://192.168.1.1/proxy/network/integration
   UNIFI_API_KEY=your-api-key
   FEEDS=bots,malware
   UNIFI_VERIFY_TLS=false
   ENV
   docker run --rm --env-file unifi.env ghcr.io/edepree/isc-unifi-connector:latest
   ```

   `UNIFI_VERIFY_TLS=false` accepts the console's self-signed certificate. To keep verification on, mount the console's CA and set `UNIFI_VERIFY_TLS` to its path instead.

3. Block the lists in UniFi. Create a firewall policy whose source (or destination) is the IP list `isc-<feed>`, with action *Block*. Later runs update the list in place, so the policy never needs editing.

## Configuration

| Variable | Required | Description |
|---|---|---|
| `UNIFI_URL` | yes | Integration API base: `https://<console-ip>/proxy/network/integration`, or `https://api.ui.com/v1/connector/consoles/<console-id>/proxy/network/integration` |
| `UNIFI_API_KEY` | yes | UniFi API key; store it as a secret |
| `FEEDS` | yes | Comma-separated list from `bots`, `malware`, `research`, `alltor`, `torexit` |
| `UNIFI_SITE` | no | Site name or internal reference (default `default`) |
| `UNIFI_VERIFY_TLS` | no | `true` (default), `false` for a console's self-signed certificate, or a path to a CA bundle |

## Behavior

- An empty feed or a failed download leaves that feed's UniFi list untouched.
- A list is only rewritten when its contents change.
- The run logs one line per feed, for example `bots: updated (+12 -9, 472 entries)`.
- Exit codes: `0` success, `1` a feed or the UniFi API failed, `2` invalid configuration.
- The container runs as UID/GID `65532`, writes nothing to disk, and works with `readOnlyRootFilesystem: true`.

## Development

```bash
just format   # apply formatting and safe lint fixes
just check    # what CI runs: format check, lint, type check, tests
just upgrade  # upgrade locked dependencies
just image    # build ghcr.io/edepree/isc-unifi-connector:<version> and :latest locally
```

The image version is the `version` in `pyproject.toml`. To release, bump it (for example `uv version --bump patch`) and merge to `master`. The [publish workflow](../.github/workflows/publish-connector.yml) builds and pushes `ghcr.io/edepree/isc-unifi-connector:<version>` and `:latest` (`linux/amd64`) only if that version isn't already published. Merges that don't bump the version publish nothing.
