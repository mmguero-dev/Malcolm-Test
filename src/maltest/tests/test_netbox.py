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
    for field in [
        "related.manufacturer",
        "related.device_type",
        "related.device_name",
        "zeek.software.software_type",
        "zeek.software.name",
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
