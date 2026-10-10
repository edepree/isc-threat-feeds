"""Fetches Internet Storm Center feeds and writes them as IPv4 CIDR lists."""

import ipaddress
import pathlib
import typing

import requests

FEEDS = {
    "bots": "threatcategory",
    "malware": "threatcategory",
    "research": "threatcategory",
    "alltor": "threatlist",
    "torexit": "threatlist",
}
HEADERS = {"User-Agent": "isc-threat-feeds (https://github.com/edepree/isc-threat-feeds)"}


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
    addresses = (ipaddress.IPv4Address(record["ipv4"]) for record in records)
    return "".join(f"{network.with_prefixlen}\n" for network in ipaddress.collapse_addresses(addresses))


def main() -> None:
    """Fetches every feed and writes `feeds/<name>.txt` only after all of them validate."""
    results = {}
    for name, kind in FEEDS.items():
        response = requests.get(f"https://isc.sans.edu/api/{kind}/{name}?json", headers=HEADERS, timeout=10)
        response.raise_for_status()
        results[name] = to_cidrs(response.json())

    output_dir = pathlib.Path("feeds")
    output_dir.mkdir(exist_ok=True)
    for name, cidrs in results.items():
        (output_dir / f"{name}.txt").write_text(cidrs)


if __name__ == "__main__":
    main()
