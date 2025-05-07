import pytest
import mmguero
import requests
import logging

LOGGER = logging.getLogger(__name__)

UPLOAD_ARTIFACTS = [
    "pcap/protocols/Tunnels.pcap",
]

ARKIME_VIEW = "Arkime Sessions"
EXPECTED_VIEWS = [
    ARKIME_VIEW,
    "Public IP Addresses",
    "Suricata Alerts",
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
    """test_arkime_views

    Test the Arkime views API

    Args:
        malcolm_url (str): URL for connecting to the Malcolm instance
        malcolm_http_auth (HTTPBasicAuth): username and password for the Malcolm instance
    """
    response = requests.get(
        f"{malcolm_url}/arkime/api/views",
        headers={"Content-Type": "application/json"},
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    views = [x.get("name") for x in mmguero.DeepGet(response.json(), ["data"], []) if 'name' in x]
    LOGGER.debug(views)
    assert all(x in views for x in EXPECTED_VIEWS)


@pytest.mark.pcap
@pytest.mark.arkime
def test_arkime_sessions(
    malcolm_url,
    malcolm_http_auth,
    artifact_hash_map,
):
    """test_arkime_sessions

    Test the Arkime sessions API

    Args:
        malcolm_url (str): URL for connecting to the Malcolm instance
        malcolm_http_auth (HTTPBasicAuth): username and password for the Malcolm instance
        artifact_hash_map (defaultdict(lambda: None)): a map of artifact files' full path to their file hash
    """
    for viewName in EXPECTED_VIEWS:
        response = requests.post(
            f"{malcolm_url}/arkime/api/sessions",
            headers={"Content-Type": "application/json"},
            json={
                "date": "-1",
                "order": "firstPacket:desc",
                "view": viewName,
                "expression": f"tags == [{','.join([artifact_hash_map[x] for x in mmguero.GetIterable(UPLOAD_ARTIFACTS)])}]",
            },
            allow_redirects=True,
            auth=malcolm_http_auth,
            verify=False,
        )
        response.raise_for_status()
        sessions = response.json()
        LOGGER.debug(f"{viewName}: {sessions}")
        assert sessions.get("data", [])


@pytest.mark.pcap
@pytest.mark.arkime
def test_arkime_connections(
    malcolm_url,
    malcolm_http_auth,
    artifact_hash_map,
):
    """test_arkime_connections

    Test the Arkime connections API

    Args:
        malcolm_url (str): URL for connecting to the Malcolm instance
        malcolm_http_auth (HTTPBasicAuth): username and password for the Malcolm instance
        artifact_hash_map (defaultdict(lambda: None)): a map of artifact files' full path to their file hash
    """
    response = requests.post(
        f"{malcolm_url}/arkime/api/connections",
        headers={"Content-Type": "application/json"},
        json={
            "date": "-1",
            "expression": f"tags == [{','.join([artifact_hash_map[x] for x in mmguero.GetIterable(UPLOAD_ARTIFACTS)])}]",
        },
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    connections = response.json()
    LOGGER.debug(connections)
    assert connections.get("links", [])
    assert connections.get("nodes", [])


@pytest.mark.pcap
@pytest.mark.arkime
def test_arkime_pcap_payload(
    malcolm_url,
    malcolm_http_auth,
    artifact_hash_map,
):
    """test_arkime_pcap_payload

    Test the Arkime sessions/pcap API (download a PCAP payload)

    Args:
        malcolm_url (str): URL for connecting to the Malcolm instance
        malcolm_http_auth (HTTPBasicAuth): username and password for the Malcolm instance
        artifact_hash_map (defaultdict(lambda: None)): a map of artifact files' full path to their file hash
    """
    response = requests.post(
        f"{malcolm_url}/arkime/api/sessions",
        headers={"Content-Type": "application/json"},
        json={
            "date": "-1",
            "order": "firstPacket:desc",
            "view": ARKIME_VIEW,
            "length": "10",
            "expression": f"tags == [{','.join([artifact_hash_map[x] for x in mmguero.GetIterable(UPLOAD_ARTIFACTS)])}] && databytes >= 10000",
        },
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    sessionsData = response.json().get("data")
    assert sessionsData
    sessionsIds = [x["id"] for x in sessionsData if "id" in x]
    assert sessionsIds
    response = requests.get(
        f"{malcolm_url}/arkime/api/sessions/pcap/sessions.pcap",
        params={"date": "-1", "ids": ','.join(sessionsIds)},
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    LOGGER.debug(f"{','.join(sessionsIds)}: {len(response.content)}")
    assert len(response.content) >= 10000


@pytest.mark.pcap
@pytest.mark.arkime
def test_arkime_spiview(
    malcolm_url,
    malcolm_http_auth,
    artifact_hash_map,
):
    """test_arkime_spiview

    Test the Arkime SPIview API

    Args:
        malcolm_url (str): URL for connecting to the Malcolm instance
        malcolm_http_auth (HTTPBasicAuth): username and password for the Malcolm instance
        artifact_hash_map (defaultdict(lambda: None)): a map of artifact files' full path to their file hash
    """
    response = requests.post(
        f"{malcolm_url}/arkime/api/spiview",
        headers={"Content-Type": "application/json"},
        json={
            "startTime": "1614556800",
            "stopTime": "1614643200",
            "order": "firstPacket:desc",
            "spi": "source.ip,destination.ip,event.provider,event.dataset",
            "expression": f"tags == [{','.join([artifact_hash_map[x] for x in mmguero.GetIterable(UPLOAD_ARTIFACTS)])}]",
        },
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    spiview = response.json().get("spi", [])
    LOGGER.debug(spiview)
    assert spiview


@pytest.mark.pcap
@pytest.mark.arkime
def test_arkime_spigraph(
    malcolm_url,
    malcolm_http_auth,
    artifact_hash_map,
):
    """test_arkime_spigraph

    Test the Arkime SPIgraph API

    Args:
        malcolm_url (str): URL for connecting to the Malcolm instance
        malcolm_http_auth (HTTPBasicAuth): username and password for the Malcolm instance
        artifact_hash_map (defaultdict(lambda: None)): a map of artifact files' full path to their file hash
    """
    response = requests.post(
        f"{malcolm_url}/arkime/api/spigraph",
        headers={"Content-Type": "application/json"},
        json={
            "startTime": "1614556800",
            "stopTime": "1614643200",
            "order": "firstPacket:desc",
            "field": "network.protocol",
            "expression": f"tags == [{','.join([artifact_hash_map[x] for x in mmguero.GetIterable(UPLOAD_ARTIFACTS)])}]",
        },
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    spigraph = response.json().get("items", [])
    LOGGER.debug(spigraph)
    assert spigraph


@pytest.mark.pcap
@pytest.mark.arkime
def test_arkime_files(
    malcolm_url,
    malcolm_http_auth,
):
    """test_arkime_files

    Test the Arkime files API

    Args:
        malcolm_url (str): URL for connecting to the Malcolm instance
        malcolm_http_auth (HTTPBasicAuth): username and password for the Malcolm instance
    """
    response = requests.get(
        f"{malcolm_url}/arkime/api/files",
        headers={"Content-Type": "application/json"},
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    files = mmguero.DeepGet(response.json(), ["data"], [])
    LOGGER.debug(files)
    assert files


@pytest.mark.arkime
def test_arkime_fields(
    malcolm_url,
    malcolm_http_auth,
):
    """test_arkime_fields

    Test the Arkime fields API

    Args:
        malcolm_url (str): URL for connecting to the Malcolm instance
        malcolm_http_auth (HTTPBasicAuth): username and password for the Malcolm instance
    """
    response = requests.get(
        f"{malcolm_url}/arkime/api/fields",
        headers={"Content-Type": "application/json"},
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    fields = response.json()
    LOGGER.debug(fields)
    assert fields


@pytest.mark.arkime
def test_arkime_valueactions(
    malcolm_url,
    malcolm_http_auth,
):
    """test_arkime_valueactions

    Test the Arkime valueactions API

    Args:
        malcolm_url (str): URL for connecting to the Malcolm instance
        malcolm_http_auth (HTTPBasicAuth): username and password for the Malcolm instance
    """
    response = requests.get(
        f"{malcolm_url}/arkime/api/valueactions",
        headers={"Content-Type": "application/json"},
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    valueactions = response.json()
    LOGGER.debug(valueactions)
    assert valueactions


@pytest.mark.arkime
def test_arkime_fieldactions(
    malcolm_url,
    malcolm_http_auth,
):
    """test_arkime_fieldactions

    Test the Arkime fieldactions API

    Args:
        malcolm_url (str): URL for connecting to the Malcolm instance
        malcolm_http_auth (HTTPBasicAuth): username and password for the Malcolm instance
    """
    response = requests.get(
        f"{malcolm_url}/arkime/api/fieldactions",
        headers={"Content-Type": "application/json"},
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    fieldactions = response.json()
    LOGGER.debug(fieldactions)
    assert fieldactions


@pytest.mark.pcap
@pytest.mark.arkime
def test_arkime_unique(
    malcolm_url,
    malcolm_http_auth,
    artifact_hash_map,
):
    """test_arkime_unique

    Test the Arkime unique API

    Args:
        malcolm_url (str): URL for connecting to the Malcolm instance
        malcolm_http_auth (HTTPBasicAuth): username and password for the Malcolm instance
        artifact_hash_map (defaultdict(lambda: None)): a map of artifact files' full path to their file hash
    """
    response = requests.post(
        f"{malcolm_url}/arkime/api/unique",
        headers={"Content-Type": "application/json"},
        json={
            "date": "-1",
            "order": "firstPacket:desc",
            "expression": f"tags == [{','.join([artifact_hash_map[x] for x in mmguero.GetIterable(UPLOAD_ARTIFACTS)])}]",
            "field": "event.provider",
        },
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    unique = response.content.decode().splitlines()
    LOGGER.debug(unique)
    assert all([x in unique for x in EXPECTED_EVENT_PROVIDERS])
