import pytest
import mmguero
import requests
import logging

LOGGER = logging.getLogger(__name__)

UPLOAD_ARTIFACTS = [
    "other/Cyberville.pcap",
]

NETBOX_ENRICH = True


@pytest.mark.mapi
@pytest.mark.netbox
@pytest.mark.pcap
def test_cyberville(
    malcolm_http_auth,
    malcolm_url,
    pcap_hash_map,
):
    assert all([pcap_hash_map.get(x, None) for x in mmguero.GetIterable(UPLOAD_ARTIFACTS)])

    response = requests.post(
        f"{malcolm_url}/mapi/agg/event.dataset",
        headers={"Content-Type": "application/json"},
        json={
            "from": "0",
            "filter": {
                "related.site": "Cyberville",
                "tags": [pcap_hash_map[x] for x in mmguero.GetIterable(UPLOAD_ARTIFACTS)],
            },
        },
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    buckets = {
        item['key']: item['doc_count'] for item in mmguero.DeepGet(response.json(), ['event.dataset', 'buckets'], [])
    }
    LOGGER.debug(buckets)
    assert buckets
