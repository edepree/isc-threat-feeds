"""Fetches Internet Storm Center feeds and writes them as IPv4 CIDR lists."""

import http
import ipaddress
import pathlib
import time
import typing

import requests

FEEDS = {
    "bots": "threatcategory",
    "malware": "threatcategory",
    "research": "threatcategory",
    "alltor": "threatlist",
    "torexit": "threatlist",
}

OUTPUT_DIR = pathlib.Path(__file__).resolve().parent.parent / "feeds"
# ISC asks for contact details in the User-Agent
HEADERS = {
    "User-Agent": "isc-threat-feeds (https://github.com/edepree/isc-threat-feeds; edepree@users.noreply.github.com)"
}


def to_cidrs(records: typing.Any) -> str:  # noqa: ANN401 - raw JSON from the ISC API is untyped until validated
    """Collapses ISC records into newline-delimited CIDRs.

    Args:
        records: Decoded JSON from the ISC API, expected to be a list of objects with an `ipv4` key.

    Returns:
        The collapsed networks in CIDR notation, one per line, with a trailing newline.

    Raises:
        ValueError: If `records` is not a non-empty list or contains an invalid address.
    """
    if not isinstance(records, list):
        raise ValueError("unexpected response shape")
    if not records:
        raise ValueError("empty feed")
    networks = (ipaddress.IPv4Network(record["ipv4"]) for record in records)
    return "".join(f"{network.with_prefixlen}\n" for network in ipaddress.collapse_addresses(networks))


def fetch(url: str) -> typing.Any:  # noqa: ANN401 - raw JSON from the ISC API is untyped until validated
    """Fetches `url` as JSON, waiting and retrying once if ISC answers 429.

    Args:
        url: The ISC API URL.

    Returns:
        The decoded JSON body.

    Raises:
        requests.HTTPError: If the response, or the retry after a 429, is an error.
    """
    response = requests.get(url, headers=HEADERS, timeout=10)

    if response.status_code == http.HTTPStatus.TOO_MANY_REQUESTS:
        # shortcut: HTTP-date Retry-After values fall back to the default, parse them if ISC starts sending them
        retry_after = response.headers.get("Retry-After", "")

        if retry_after.isdigit():
            delay = int(retry_after)
        else:
            delay = 300  # ISC asks clients to back off five minutes after a 429

        time.sleep(min(delay, 900))
        response = requests.get(url, headers=HEADERS, timeout=10)

    response.raise_for_status()
    return response.json()


def main() -> None:
    """Fetches every feed and writes `OUTPUT_DIR/<name>.txt` only after all of them validate."""
    results = {}
    for name, kind in FEEDS.items():
        results[name] = to_cidrs(fetch(f"https://isc.sans.edu/api/{kind}/{name}?json"))

    OUTPUT_DIR.mkdir(exist_ok=True)
    for name, cidrs in results.items():
        (OUTPUT_DIR / f"{name}.txt").write_text(cidrs)


if __name__ == "__main__":
    main()
