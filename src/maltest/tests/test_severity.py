import logging
import mmguero
import pytest
import requests

LOGGER = logging.getLogger(__name__)

UPLOAD_ARTIFACTS = [
    "pcap/protocols/DNS.pcap",
    "pcap/protocols/FTP.pcap",
    "pcap/protocols/HTTP_1.pcap",
    "pcap/protocols/HTTP_2.pcap",
    "pcap/protocols/S7comm.pcap",
    "pcap/protocols/SMB.pcap",
    "pcap/protocols/OpenVPN.pcap",
]

EXPECTED_SEVERITY_TAGS = [
    "Cleartext password",
    "Connection aborted (originator)",
    "Connection aborted (responder)",
    "Connection attempt rejected",
    "Connection attempt, no reply",
    # "Cross-segment traffic",
    "External traffic",
    "File transfer (high concern)",
    "File transfer (medium concern)",
    # "File transfer",
    # "High entropy domain",
    "High volume connection",
    "Inbound traffic",
    "Insecure or outdated protocol",
    # "Intelligence",
    # "Internal traffic",
    "Long connection",
    "MITRE ATT&CK for ICS framework tactic or technique",
    "MITRE ATT&CK framework tactic or technique",
    "Notice (other)",
    "Notice (protocol)",
    "Notice (scan)",
    "Notice (vulnerability)",
    "Outbound traffic",
    "Sensitive country",
    "Service on non-standard port",
    "Signature (capa)",
    "Signature (ClamAV)",
    "Signature (YARA)",
    "Signature",
    "Suricata Alert",
    "Tunneled traffic",
    "VPN traffic",
    "Weird",
]


@pytest.mark.mapi
@pytest.mark.pcap
def test_severity_tags(
    malcolm_http_auth,
    malcolm_url,
    artifact_hash_map,
):
    """test_severity_tags

    Test that the expected event.severity_tags are generated correctly

    Args:
        malcolm_http_auth (HTTPBasicAuth): username and password for the Malcolm instance
        malcolm_url (str): URL for connecting to the Malcolm instance
        artifact_hash_map (defaultdict(lambda: None)): a map of artifact files' full path to their file hash
    """
    assert all([artifact_hash_map.get(x, None) for x in mmguero.GetIterable(UPLOAD_ARTIFACTS)])

    response = requests.post(
        f"{malcolm_url}/mapi/agg/event.severity_tags",
        headers={"Content-Type": "application/json"},
        json={
            "from": "0",
            "filter": {
                # can't filter on tags, because signatures(_carved).log doesn't get tags :(
                # "tags": [artifact_hash_map[x] for x in mmguero.GetIterable(UPLOAD_ARTIFACTS)],
                "!event.severity_tags": None,
            },
        },
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    buckets = {
        item['key']: item['doc_count']
        for item in mmguero.DeepGet(response.json(), ['event.severity_tags', 'buckets'], [])
    }
    LOGGER.debug(buckets)
    LOGGER.debug([x for x in EXPECTED_SEVERITY_TAGS if (buckets.get(x, 0) == 0)])
    assert all([(buckets.get(x, 0) > 0) for x in EXPECTED_SEVERITY_TAGS])
