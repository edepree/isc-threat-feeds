"""Syncs published ISC threat feeds into UniFi Network traffic matching lists."""

import collections.abc
import dataclasses
import ipaddress
import logging
import os
import pathlib
import signal
import sys
import typing

import requests
import urllib3

FEEDS: tuple[str, ...] = ("bots", "malware", "research", "alltor", "torexit")
FEED_URL = "https://raw.githubusercontent.com/edepree/isc-threat-feeds/master/feeds/{feed}.txt"
USER_AGENT = "isc-unifi-connector (https://github.com/edepree/isc-threat-feeds)"
TIMEOUT = 30
PAGE_SIZE = 200

type ApiObject = dict[str, typing.Any]

log = logging.getLogger("unifi_connector")


class ConfigError(Exception):
    """Raised when the environment does not describe a usable configuration."""


@dataclasses.dataclass(frozen=True)
class Config:
    """Connector settings read from the environment."""

    url: str
    api_key: str
    feeds: tuple[str, ...]
    site: str
    verify: bool | str


def _required(env: collections.abc.Mapping[str, str], name: str) -> str:
    value = env.get(name, "").strip()
    if not value:
        raise ConfigError(f"{name} is required")
    return value


def load_config(env: collections.abc.Mapping[str, str]) -> Config:
    """Builds the connector configuration from environment variables.

    Args:
        env: Environment variables, usually `os.environ`.

    Returns:
        The validated configuration.

    Raises:
        ConfigError: If a required variable is missing or any value is invalid.
    """
    url = _required(env, "UNIFI_URL").rstrip("/")
    api_key = _required(env, "UNIFI_API_KEY")

    feeds = tuple(dict.fromkeys(f.strip().lower() for f in _required(env, "FEEDS").split(",") if f.strip()))

    if not feeds:
        raise ConfigError("FEEDS must name at least one feed")

    unknown = [f for f in feeds if f not in FEEDS]

    if unknown:
        raise ConfigError(f"FEEDS has unknown feeds: {', '.join(unknown)} (choose from {', '.join(FEEDS)})")

    raw_verify = env.get("UNIFI_VERIFY_TLS", "true").strip()
    verify: bool | str

    if raw_verify.lower() in {"true", "false"}:
        verify = raw_verify.lower() == "true"
    elif pathlib.Path(raw_verify).is_file():
        verify = raw_verify
    else:
        raise ConfigError(f"UNIFI_VERIFY_TLS must be true, false, or an existing CA bundle path: {raw_verify}")

    site = env.get("UNIFI_SITE", "").strip() or "default"
    return Config(url=url, api_key=api_key, feeds=feeds, site=site, verify=verify)


def parse_feed(text: str) -> list[str]:
    """Parses a newline-delimited IPv4 CIDR list.

    Args:
        text: Feed contents; blank lines are ignored.

    Returns:
        Sorted, de-duplicated networks in CIDR notation.

    Raises:
        ValueError: If any line is not an IPv4 network or the feed has no entries.
    """
    networks = {ipaddress.IPv4Network(line.strip()) for line in text.splitlines() if line.strip()}
    if not networks:
        raise ValueError("empty feed")
    return [network.with_prefixlen for network in sorted(networks)]


def feed_session() -> requests.Session:
    """Returns a session for downloading feeds, kept separate so UniFi credentials never leave for GitHub."""
    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT
    return session


def fetch_feed(session: requests.Session, feed: str) -> list[str]:
    """Downloads and parses one published feed.

    Args:
        session: Session from `feed_session`.
        feed: Feed name from `FEEDS`.

    Returns:
        The feed's networks, as returned by `parse_feed`.

    Raises:
        requests.RequestException: If the download fails.
        ValueError: If the content is not a valid, non-empty IPv4 list.
    """
    response = session.get(FEED_URL.format(feed=feed), timeout=TIMEOUT)
    response.raise_for_status()
    return parse_feed(response.text)


class UnifiError(Exception):
    """Raised when the UniFi API returns an error or unexpected data."""


def format_error(response: requests.Response) -> str:
    """Summarizes a UniFi error response, tolerating non-JSON bodies from proxies.

    Args:
        response: The failed response.

    Returns:
        `<statusCode> <code> <message>[ requestId=<id>]`, or `<status> <body prefix>` for non-JSON bodies.
    """
    try:
        body = response.json()
    except requests.JSONDecodeError:
        body = None

    if not isinstance(body, dict):
        return f"{response.status_code} {response.text[:200]}"

    summary = f"{body.get('statusCode', response.status_code)} {body.get('code')} {body.get('message')}"

    return f"{summary} requestId={body['requestId']}" if body.get("requestId") else summary


def list_body(name: str, cidrs: list[str]) -> ApiObject:
    """Builds the create/update payload for an IPv4 traffic matching list."""
    # UniFi rejects a /32 SUBNET (422 invalid-items); single hosts must be IP_ADDRESS.
    items = [
        {"type": "IP_ADDRESS", "value": c.removesuffix("/32")} if c.endswith("/32") else {"type": "SUBNET", "value": c}
        for c in cidrs
    ]
    return {"type": "IPV4_ADDRESSES", "name": name, "items": items}


class UnifiClient:
    """Minimal client for the UniFi Network Integration API."""

    def __init__(
        self, base_url: str, api_key: str, verify: bool | str, session: requests.Session | None = None
    ) -> None:
        """Initializes the client.

        Args:
            base_url: Integration API base URL without a trailing slash.
            api_key: UniFi API key, sent as `X-API-KEY`.
            verify: `requests` TLS verification setting.
            session: Session to use; a new one is created when omitted.
        """
        self.base_url = base_url
        self.session = session or requests.Session()
        self.session.headers.update({"X-API-KEY": api_key, "Accept": "application/json", "User-Agent": USER_AGENT})
        self.verify = verify

    def request(self, method: str, path: str, **kwargs: typing.Any) -> typing.Any:  # noqa: ANN401 - decoded JSON
        """Sends a request and returns the decoded JSON body.

        Args:
            method: HTTP method.
            path: Path below the base URL, starting with `/`.
            **kwargs: Passed through to `requests.Session.request`.

        Returns:
            The decoded JSON body, or None when the body is empty.

        Raises:
            UnifiError: If the response status is not 2xx, including redirects.
        """
        # No redirects: requests would resend X-API-KEY to the new location. Per-call verify beats REQUESTS_CA_BUNDLE.
        response = self.session.request(
            method, f"{self.base_url}{path}", timeout=TIMEOUT, verify=self.verify, allow_redirects=False, **kwargs
        )

        if not 200 <= response.status_code < 300:  # noqa: PLR2004
            raise UnifiError(format_error(response))

        return response.json() if response.content else None

    def paginate(self, path: str) -> list[ApiObject]:
        """Collects every item from a paged list endpoint."""
        items: list[ApiObject] = []
        offset = 0

        while True:
            page = self.request("GET", path, params={"offset": offset, "limit": PAGE_SIZE})
            items.extend(page["data"])
            offset += PAGE_SIZE

            if offset >= page["totalCount"]:
                return items

    def site_id(self, site: str) -> str:
        """Resolves a site name or internal reference to its ID.

        Raises:
            UnifiError: If no site matches.
        """
        for candidate in self.paginate("/v1/sites"):
            if site in {candidate.get("name"), candidate.get("internalReference")}:
                return candidate["id"]

        raise UnifiError(f"site not found: {site}")

    def lists(self, site_id: str) -> list[ApiObject]:
        """Returns every traffic matching list on a site."""
        return self.paginate(f"/v1/sites/{site_id}/traffic-matching-lists")

    def create_list(self, site_id: str, name: str, cidrs: list[str]) -> None:
        """Creates an IPv4 traffic matching list."""
        self.request("POST", f"/v1/sites/{site_id}/traffic-matching-lists", json=list_body(name, cidrs))

    def update_list(self, site_id: str, list_id: str, name: str, cidrs: list[str]) -> None:
        """Replaces the contents of an IPv4 traffic matching list."""
        self.request("PUT", f"/v1/sites/{site_id}/traffic-matching-lists/{list_id}", json=list_body(name, cidrs))


def _normalized(items: list[ApiObject]) -> set[str]:
    # Items the connector would not write (ranges, unparsable values) stay distinct so they force an update.
    values = set()
    for item in items:
        if item.get("type") not in {"SUBNET", "IP_ADDRESS"}:
            values.add(repr(item))
            continue
        try:
            values.add(ipaddress.IPv4Network(item["value"]).with_prefixlen)
        except (KeyError, ValueError):
            values.add(repr(item))

    return values


def sync_feed(client: UnifiClient, site_id: str, feed: str, cidrs: list[str], existing: list[ApiObject]) -> str:
    """Creates or replaces the `isc-<feed>` list so it holds exactly `cidrs`.

    Args:
        client: UniFi API client.
        site_id: Site holding the list.
        feed: Feed name from `FEEDS`.
        cidrs: Desired networks, as returned by `fetch_feed`.
        existing: Every traffic matching list on the site.

    Returns:
        A one-line summary of the action taken.

    Raises:
        ValueError: If the list name is ambiguous or used by a non-IPv4 list.
    """
    name = f"isc-{feed}"
    desired = set(cidrs)
    matches = [candidate for candidate in existing if candidate.get("name") == name]

    if len(matches) > 1:
        raise ValueError(f"{len(matches)} lists named {name}; remove the extras")

    if not matches:
        client.create_list(site_id, name, cidrs)
        return f"{feed}: created (+{len(desired)} -0, {len(desired)} entries)"

    current = matches[0]

    if current.get("type") != "IPV4_ADDRESSES":
        raise ValueError(f"{name} is a {current.get('type')} list, expected IPV4_ADDRESSES")

    actual = _normalized(current.get("items", []))
    added, removed = len(desired - actual), len(actual - desired)

    if added or removed:
        client.update_list(site_id, current["id"], name, cidrs)
        action = "updated"
    else:
        action = "unchanged"

    return f"{feed}: {action} (+{added} -{removed}, {len(desired)} entries)"


def main(env: collections.abc.Mapping[str, str] = os.environ) -> int:
    """Syncs every configured feed and returns the process exit code."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        config = load_config(env)
    except ConfigError as err:
        log.error("invalid configuration: %s", err)
        return 2

    if config.verify is False:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        log.warning("TLS verification is disabled for UniFi requests")

    client = UnifiClient(config.url, config.api_key, config.verify)

    try:
        site_id = client.site_id(config.site)
        existing = client.lists(site_id)
    except (UnifiError, requests.RequestException) as err:
        log.error("UniFi: %s", err)
        return 1

    downloads = feed_session()
    failed = False

    for feed in config.feeds:
        try:
            log.info(sync_feed(client, site_id, feed, fetch_feed(downloads, feed), existing))
        except (UnifiError, requests.RequestException, ValueError, KeyError) as err:
            log.error("%s: failed: %s", feed, err)
            failed = True

    return 1 if failed else 0


if __name__ == "__main__":
    # Python as PID 1 ignores SIGTERM by default, which would stall pod shutdown until SIGKILL.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    sys.exit(main())
