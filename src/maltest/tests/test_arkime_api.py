import pytest
import mmguero
import requests
import logging
import json

LOGGER = logging.getLogger(__name__)

UPLOAD_ARTIFACTS = [
    "protocols/HTTP_1.pcap",
]

EXPECTED_VIEWS = [
    "Arkime Sessions",
    "Public IP Addresses",
    "Suricata Alerts",
    "Suricata Logs",
    "Uninventoried Internal Assets",
    "Uninventoried Observed Services",
    "Zeek Exclude conn.log",
    "Zeek Logs",
    "Zeek conn.log",
]

EXPECTED_EVENT_PROVIDERS = ['zeek', 'arkime', 'suricata']


@pytest.mark.arkime
def test_arkime_views(
    malcolm_url,
    malcolm_http_auth,
):
    response = requests.get(
        f"{malcolm_url}/arkime/api/views",
        headers={"Content-Type": "application/json"},
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    views = [x.get("name") for x in mmguero.DeepGet(response.json(), ["data"], []) if 'name' in x]
    assert all(x in views for x in EXPECTED_VIEWS)


@pytest.mark.pcap
@pytest.mark.arkime
def test_arkime_sessions(
    malcolm_url,
    malcolm_http_auth,
    pcap_hash_map,
):
    for viewName in EXPECTED_VIEWS:
        response = requests.post(
            f"{malcolm_url}/arkime/api/sessions",
            headers={"Content-Type": "application/json"},
            json={
                "date": "-1",
                "order": "firstPacket:desc",
                "view": viewName,
                "expression": f"tags == [{','.join([pcap_hash_map[x] for x in mmguero.GetIterable(UPLOAD_ARTIFACTS)])}]",
            },
            allow_redirects=True,
            auth=malcolm_http_auth,
            verify=False,
        )
        response.raise_for_status()
        sessions = response.json()
        assert sessions.get("data", [])


@pytest.mark.pcap
@pytest.mark.arkime
def test_arkime_spiview(
    malcolm_url,
    malcolm_http_auth,
    pcap_hash_map,
):
    response = requests.post(
        f"{malcolm_url}/arkime/api/spiview",
        headers={"Content-Type": "application/json"},
        json={
            "startTime": "1614556800",
            "stopTime": "1614643200",
            "order": "firstPacket:desc",
            "spi": "source.ip,destination.ip,event.provider,event.dataset",
            "expression": f"tags == [{','.join([pcap_hash_map[x] for x in mmguero.GetIterable(UPLOAD_ARTIFACTS)])}]",
        },
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    spiview = response.json().get("spi", [])
    assert spiview


@pytest.mark.pcap
@pytest.mark.arkime
def test_arkime_spigraph(
    malcolm_url,
    malcolm_http_auth,
    pcap_hash_map,
):
    response = requests.post(
        f"{malcolm_url}/arkime/api/spigraph",
        headers={"Content-Type": "application/json"},
        json={
            "startTime": "1614556800",
            "stopTime": "1614643200",
            "order": "firstPacket:desc",
            "field": "network.protocol",
            "expression": f"tags == [{','.join([pcap_hash_map[x] for x in mmguero.GetIterable(UPLOAD_ARTIFACTS)])}]",
        },
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    spigraph = response.json().get("items", [])
    assert spigraph


@pytest.mark.pcap
@pytest.mark.arkime
def test_arkime_files(
    malcolm_url,
    malcolm_http_auth,
):
    response = requests.get(
        f"{malcolm_url}/arkime/api/files",
        headers={"Content-Type": "application/json"},
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    files = mmguero.DeepGet(response.json(), ["data"], [])
    assert files


@pytest.mark.arkime
def test_arkime_fields(
    malcolm_url,
    malcolm_http_auth,
):
    response = requests.get(
        f"{malcolm_url}/arkime/api/fields",
        headers={"Content-Type": "application/json"},
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    fields = response.json()
    assert fields


@pytest.mark.arkime
def test_arkime_valueactions(
    malcolm_url,
    malcolm_http_auth,
):
    response = requests.get(
        f"{malcolm_url}/arkime/api/valueactions",
        headers={"Content-Type": "application/json"},
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    valueactions = response.json()
    assert valueactions


@pytest.mark.arkime
def test_arkime_fieldactions(
    malcolm_url,
    malcolm_http_auth,
):
    response = requests.get(
        f"{malcolm_url}/arkime/api/fieldactions",
        headers={"Content-Type": "application/json"},
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    fieldactions = response.json()
    assert fieldactions


@pytest.mark.pcap
@pytest.mark.arkime
def test_arkime_unique(
    malcolm_url,
    malcolm_http_auth,
    pcap_hash_map,
):
    response = requests.post(
        f"{malcolm_url}/arkime/api/unique",
        headers={"Content-Type": "application/json"},
        json={
            "date": "-1",
            "order": "firstPacket:desc",
            "expression": f"tags == [{','.join([pcap_hash_map[x] for x in mmguero.GetIterable(UPLOAD_ARTIFACTS)])}]",
            "field": "event.provider",
        },
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    unique = response.content.decode().splitlines()
    assert all([x in unique for x in EXPECTED_EVENT_PROVIDERS])
