import pytest
import requests
import logging

LOGGER = logging.getLogger(__name__)


@pytest.mark.vm
def test_vm_exists(
    malcolm_vm_info,
):
    LOGGER.debug(malcolm_vm_info)
    assert isinstance(malcolm_vm_info, dict) and malcolm_vm_info.get("ip", None)


@pytest.mark.mapi
def test_ping(
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
    responseData = response.json()
    LOGGER.debug(responseData)
    assert responseData.get('ping', '') == 'pong'


@pytest.mark.opensearch
def test_db_health(
    malcolm_url,
    database_objs,
):
    dbObjs = database_objs
    healthDict = dict(
        dbObjs.DatabaseClass(
            hosts=[
                f"{malcolm_url}/mapi/opensearch",
            ],
            **dbObjs.DatabaseInitArgs,
        ).cluster.health()
    )
    LOGGER.debug(healthDict)
    assert healthDict.get("status", "unknown") in ["green", "yellow"]
