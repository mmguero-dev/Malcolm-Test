import pytest
import mmguero
import requests
import logging

LOGGER = logging.getLogger(__name__)


@pytest.mark.mapi
@pytest.mark.beats
def test_nginx_logs(
    malcolm_http_auth,
    malcolm_url,
    artifact_hash_map,
):
    """test_nginx_logs

    Test the the NGINX access and error logs that are generated by Malcolm's access itself (NGINX_LOG_ACCESS_AND_ERRORS)
        get logged/parsed/indexed correctly.

    Args:
        malcolm_http_auth (HTTPBasicAuth): username and password for the Malcolm instance
        malcolm_url (str): URL for connecting to the Malcolm instance
        artifact_hash_map (defaultdict(lambda: None)): a map of artifact files' full path to their file hash
    """
    for field in [
        "http.request.method",
        "http.response.status_code",
        "log.file.path",
        "url.original",
        "user_agent.original",
    ]:
        response = requests.post(
            f"{malcolm_url}/mapi/agg/{field}",
            headers={"Content-Type": "application/json"},
            json={
                "from": "0",
                "limit": "10",
                "doctype": "host",
                "filter": {
                    "event.module": "nginx",
                },
            },
            allow_redirects=True,
            auth=malcolm_http_auth,
            verify=False,
        )
        response.raise_for_status()
        LOGGER.debug(response.json())
        buckets = {item['key']: item['doc_count'] for item in mmguero.DeepGet(response.json(), [field, 'buckets'], [])}
        LOGGER.debug(buckets)
        assert buckets
