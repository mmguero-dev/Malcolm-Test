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
