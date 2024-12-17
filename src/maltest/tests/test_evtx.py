import logging
import mmguero
import pytest
import requests

LOGGER = logging.getLogger(__name__)

UPLOAD_ARTIFACTS = [
    "evtx/sbousseaden-EVTX-ATTACK-SAMPLES.7z",
]


@pytest.mark.hostlogs
@pytest.mark.mapi
def test_all_evtx(
    malcolm_http_auth,
    malcolm_url,
    artifact_hash_map,  # actually artifact_hash_map holds evtx files too...
):
    assert all([artifact_hash_map.get(x, None) for x in mmguero.GetIterable(UPLOAD_ARTIFACTS)])

    response = requests.post(
        f"{malcolm_url}/mapi/agg/event.dataset",
        headers={"Content-Type": "application/json"},
        json={
            "from": "0",
            "doctype": "host",
            "filter": {
                "event.module": "winlog",
                "!event.dataset": None,
                "tags": [artifact_hash_map[x] for x in mmguero.GetIterable(UPLOAD_ARTIFACTS)],
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
