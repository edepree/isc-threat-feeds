import http
import ipaddress
import pathlib

import pytest
import requests

import isc_threat_feeds


class FakeResponse:
    def __init__(self, payload: object, status: int = 200, headers: dict[str, str] | None = None) -> None:
        self.payload = payload
        self.status_code = status
        self.headers = headers or {}

    def raise_for_status(self) -> None:
        if self.status_code >= http.HTTPStatus.BAD_REQUEST:
            raise requests.HTTPError(f"{self.status_code}")

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
    monkeypatch.setattr(isc_threat_feeds, "OUTPUT_DIR", tmp_path / "feeds")
    monkeypatch.setattr(requests, "get", lambda *_args, **_kwargs: FakeResponse([{"ipv4": "1.2.3.4"}]))

    isc_threat_feeds.main()

    written = sorted(p.name for p in (tmp_path / "feeds").iterdir())
    assert written == sorted(f"{name}.txt" for name in isc_threat_feeds.FEEDS)
    assert (tmp_path / "feeds" / "bots.txt").read_text() == "1.2.3.4/32\n"


def test_main_writes_nothing_when_any_feed_fails(monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path) -> None:
    def fake_get(url: str, **_kwargs: object) -> FakeResponse:
        return FakeResponse([], status=503) if "torexit" in url else FakeResponse([{"ipv4": "1.2.3.4"}])

    monkeypatch.setattr(isc_threat_feeds, "OUTPUT_DIR", tmp_path / "feeds")
    monkeypatch.setattr(requests, "get", fake_get)

    with pytest.raises(requests.HTTPError):
        isc_threat_feeds.main()

    assert not (tmp_path / "feeds").exists()


@pytest.mark.parametrize(("retry_after", "expected_sleep"), [("7", 7), ("", 300), ("99999", 900)])
def test_fetch_retries_once_after_429(monkeypatch: pytest.MonkeyPatch, retry_after: str, expected_sleep: int) -> None:
    responses = [
        FakeResponse(None, status=429, headers={"Retry-After": retry_after}),
        FakeResponse([{"ipv4": "1.2.3.4"}]),
    ]
    sleeps = []
    monkeypatch.setattr(requests, "get", lambda *_args, **_kwargs: responses.pop(0))
    monkeypatch.setattr(isc_threat_feeds.time, "sleep", sleeps.append)

    assert isc_threat_feeds.fetch("https://isc.sans.edu/api/x") == [{"ipv4": "1.2.3.4"}]
    assert sleeps == [expected_sleep]


def test_fetch_raises_when_retry_is_also_429(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(requests, "get", lambda *_args, **_kwargs: FakeResponse(None, status=429))
    monkeypatch.setattr(isc_threat_feeds.time, "sleep", lambda _seconds: None)

    with pytest.raises(requests.HTTPError):
        isc_threat_feeds.fetch("https://isc.sans.edu/api/x")


def test_output_dir_is_repo_root_feeds() -> None:
    assert pathlib.Path(__file__).resolve().parents[2] / "feeds" == isc_threat_feeds.OUTPUT_DIR
