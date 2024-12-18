import pytest
import mmguero
import requests
import logging

LOGGER = logging.getLogger(__name__)


@pytest.mark.mapi
@pytest.mark.beats
@pytest.mark.nginx
def test_nginx_logs(
    malcolm_http_auth,
    malcolm_url,
    artifact_hash_map,
):
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
