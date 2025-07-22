import pytest
import mmguero
import requests
import logging

LOGGER = logging.getLogger(__name__)

UPLOAD_ARTIFACTS = [
    "pcap/other/Digital Bond S4/Advantech.pcap",
    "pcap/other/Digital Bond S4/BACnet_FIU.pcap",
    "pcap/other/Digital Bond S4/BACnet_Host.pcap",
    "pcap/other/Digital Bond S4/MicroLogix56.pcap",
    "pcap/other/Digital Bond S4/Modicon.pcap",
    "pcap/other/Digital Bond S4/WinXP.pcap",
    "pcap/other/Digital Bond S4/iFix_Client86.pcap",
    "pcap/other/Digital Bond S4/iFix_Server119.pcap",
]

NETBOX_ENRICH = True


@pytest.mark.netbox
@pytest.mark.mapi
@pytest.mark.pcap
def test_netbox_cross_segment(
    malcolm_http_auth,
    malcolm_url,
    artifact_hash_map,
):
    """test_netbox_cross_segment

    After netbox enrichment/autopopulation happens, check that cross-segment traffic was detected

    Args:
        malcolm_http_auth (HTTPBasicAuth): username and password for the Malcolm instance
        malcolm_url (str): URL for connecting to the Malcolm instance
        artifact_hash_map (defaultdict(lambda: None)): a map of artifact files' full path to their file hash
    """
    response = requests.post(
        f"{malcolm_url}/mapi/agg/event.provider,source.segment.name,destination.segment.name",
        headers={"Content-Type": "application/json"},
        json={
            "from": "0",
            "filter": {
                "!source.segment.name": None,
                "!destination.segment.name": None,
                "tags": "cross_segment",
                "tags": [artifact_hash_map[x] for x in mmguero.GetIterable(UPLOAD_ARTIFACTS)],
            },
        },
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    responseJson = response.json()
    results = {}
    for providerBucket in mmguero.DeepGet(responseJson, ["event.provider", "buckets"], []):
        providerName = providerBucket["key"]
        results[providerName] = []
        for sourceSegmentBucket in mmguero.DeepGet(providerBucket, ["source.segment.name", "buckets"], [{}]):
            sourceSegmentName = sourceSegmentBucket["key"]
            for destinationSegmentBucket in mmguero.DeepGet(
                sourceSegmentBucket, ["destination.segment.name", "buckets"], [{}]
            ):
                destinationSegmentName = destinationSegmentBucket["key"]
                crossSegmentCount = destinationSegmentBucket["doc_count"]
                results[providerName].append(f"{sourceSegmentName} -> {destinationSegmentName} = {crossSegmentCount}")
    LOGGER.debug(results)
    assert results.get("zeek", None)
    assert results.get("suricata", None)


@pytest.mark.netbox
@pytest.mark.mapi
@pytest.mark.pcap
def test_netbox_enrichment(
    malcolm_http_auth,
    malcolm_url,
    artifact_hash_map,
):
    """test_netbox_enrichment

    Check for various fields populated by netbox enrichment (manufacturer, device type, device name, etc.)

    Args:
        malcolm_http_auth (HTTPBasicAuth): username and password for the Malcolm instance
        malcolm_url (str): URL for connecting to the Malcolm instance
        artifact_hash_map (defaultdict(lambda: None)): a map of artifact files' full path to their file hash
    """
    for field in [
        "destination.device.uninventoried",
        "related.device_name",
        "related.manufacturer",
        "related.uninventoried",
        "source.device.uninventoried",
        "zeek.software.name",
        "zeek.software.software_type",
    ]:
        response = requests.post(
            f"{malcolm_url}/mapi/agg/{field}",
            headers={"Content-Type": "application/json"},
            json={
                "from": "0",
                "filter": {
                    f"!{field}": None,
                    "tags": [artifact_hash_map[x] for x in mmguero.GetIterable(UPLOAD_ARTIFACTS)],
                },
            },
            allow_redirects=True,
            auth=malcolm_http_auth,
            verify=False,
        )
        response.raise_for_status()
        buckets = {item['key']: item['doc_count'] for item in mmguero.DeepGet(response.json(), [field, 'buckets'], [])}
        LOGGER.debug(buckets)
        assert buckets


@pytest.mark.netbox
@pytest.mark.mapi
@pytest.mark.pcap
def test_netbox_auto_prefixes(
    malcolm_http_auth,
    malcolm_url,
    artifact_hash_map,
):
    response = requests.get(
        f"{malcolm_url}/mapi/netbox/ipam/prefixes/",
        headers={"Content-Type": "application/json"},
        json={
            "format": "json",
        },
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()

    buckets = [
        {
            "prefix": item["prefix"],
            "description": item["description"],
            "site": item["scope"]["name"] if item.get("scope") else None,
            "tags": [tag["slug"] for tag in item.get("tags", [])],
        }
        for item in response.json().get("results", [])
    ]
    LOGGER.debug(buckets)
    assert all("malcolm-autopopulated" in p["tags"] for p in buckets)
    assert len({(p["site"], p["prefix"]) for p in buckets}) == len(
        buckets
    ), "Duplicate prefixes found for the same site"
    assert buckets


@pytest.mark.netbox
@pytest.mark.mapi
@pytest.mark.pcap
def test_netbox_auto_devices(
    malcolm_http_auth,
    malcolm_url,
    artifact_hash_map,
):
    response = requests.get(
        f"{malcolm_url}/mapi/netbox/dcim/devices/",
        headers={"Content-Type": "application/json"},
        json={
            "format": "json",
        },
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()

    buckets = [
        {
            "name": d["name"],
            "site": d["site"]["name"] if d.get("site") else None,
            "status": d["status"]["label"] if d.get("status") else None,
            "role": d["role"]["name"] if d.get("role") else None,
            "primary_ip": d["primary_ip"]["address"] if d.get("primary_ip") else None,
            "tags": [tag["slug"] for tag in d.get("tags", [])],
        }
        for d in response.json().get("results", [])
    ]
    LOGGER.debug(buckets)
    assert all("malcolm-autopopulated" in p["tags"] for p in buckets)
    assert any("hostname-unknown" in p["tags"] for p in buckets)
    assert all(p["primary_ip"] for p in buckets)
    assert buckets


@pytest.mark.netbox
@pytest.mark.mapi
@pytest.mark.pcap
def test_netbox_auto_manuf(
    malcolm_http_auth,
    malcolm_url,
    artifact_hash_map,
):
    response = requests.get(
        f"{malcolm_url}/mapi/netbox/dcim/manufacturers/",
        headers={"Content-Type": "application/json"},
        json={
            "format": "json",
        },
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()

    buckets = [
        {
            "name": m["name"],
            "tags": [tag["slug"] for tag in m.get("tags", [])],
        }
        for m in response.json().get("results", [])
    ]
    LOGGER.debug(buckets)
    assert any("malcolm-autopopulated" in m["tags"] for m in buckets)
    assert buckets
