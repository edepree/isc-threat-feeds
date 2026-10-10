import http
import ipaddress
import pathlib

import pytest
import requests

import isc_threat_feeds


class FakeResponse:
    def __init__(self, payload: object, status: int = 200) -> None:
        self.payload = payload
        self.status = status

    def raise_for_status(self) -> None:
        if self.status >= http.HTTPStatus.BAD_REQUEST:
            raise requests.HTTPError(f"{self.status}")

    def json(self) -> object:
        return self.payload


def test_to_cidrs_collapses_and_sorts() -> None:
    records = [{"ipv4": "10.0.0.1"}, {"ipv4": "192.168.1.5"}, {"ipv4": "10.0.0.0"}]
    assert isc_threat_feeds.to_cidrs(records) == "10.0.0.0/31\n192.168.1.5/32\n"


def test_to_cidrs_rejects_empty_feed() -> None:
    with pytest.raises(ValueError, match="empty feed"):
        isc_threat_feeds.to_cidrs([])


def test_to_cidrs_rejects_unexpected_shape() -> None:
    with pytest.raises(ValueError, match="unexpected response shape"):
        isc_threat_feeds.to_cidrs({"error": "x"})


def test_to_cidrs_rejects_zero_padded_octets() -> None:
    with pytest.raises(ipaddress.AddressValueError):
        isc_threat_feeds.to_cidrs([{"ipv4": "010.000.000.001"}])


def test_main_writes_every_feed(monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(requests, "get", lambda *_args, **_kwargs: FakeResponse([{"ipv4": "1.2.3.4"}]))

    isc_threat_feeds.main()

    written = sorted(p.name for p in (tmp_path / "feeds").iterdir())
    assert written == sorted(f"{name}.txt" for name in isc_threat_feeds.FEEDS)
    assert (tmp_path / "feeds" / "bots.txt").read_text() == "1.2.3.4/32\n"


def test_main_writes_nothing_when_any_feed_fails(monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path) -> None:
    def fake_get(url: str, **_kwargs: object) -> FakeResponse:
        return FakeResponse([], status=503) if "torexit" in url else FakeResponse([{"ipv4": "1.2.3.4"}])

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(requests, "get", fake_get)

    with pytest.raises(requests.HTTPError):
        isc_threat_feeds.main()

    assert not (tmp_path / "feeds").exists()
