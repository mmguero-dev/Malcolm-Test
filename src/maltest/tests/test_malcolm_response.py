import requests
import json
import mmguero


def test_malcolm_exists(
    malcolm_vm_info,
    malcolm_url,
    malcolm_http_auth,
):
    response = requests.get(
        f"{malcolm_url}/mapi/ping",
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    assert response.json().get('ping', '') == 'pong'
