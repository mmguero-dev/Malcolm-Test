import pytest
import mmguero
import requests
import logging

LOGGER = logging.getLogger(__name__)


@pytest.mark.mapi
def test_mapi_indices(
    malcolm_url,
    malcolm_http_auth,
):
    response = requests.get(
        f"{malcolm_url}/mapi/indices",
        headers={"Content-Type": "application/json"},
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    indices = {item['index']: item for item in response.json().get('indices', [])}
    LOGGER.info(indices)
    assert indices
