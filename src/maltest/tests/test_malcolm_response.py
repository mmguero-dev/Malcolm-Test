import requests
import json
import mmguero

from requests.auth import HTTPBasicAuth


def test_malcolm_exists(
    malcolm_vm_info,
    malcolm_url,
    malcolm_http_auth,
):
    try:
        response = requests.get(
            f"{malcolm_url}/mapi/ping",
            auth=malcolm_http_auth,
            verify=False,
        )
        response.raise_for_status()
        assert response.json().get('ping', '') == 'pong'
    except:
        assert False
