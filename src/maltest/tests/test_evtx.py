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
    """test_all_evtx

    Check the existance of the event.module value of winlog, which is populated from the parsing of
        Windows event logs. Note that the "doctype": "host" filter is used passed to the mapi/agg API
        so that host log data is queried instead of network log data.

    Args:
        malcolm_http_auth (HTTPBasicAuth): username and password for the Malcolm instance
        malcolm_url (str): URL for connecting to the Malcolm instance
        artifact_hash_map (defaultdict(lambda: None)): a map of artifact files' full path to their file hash
    """
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
