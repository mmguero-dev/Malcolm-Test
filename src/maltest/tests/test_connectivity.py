import pytest
import requests
import logging

LOGGER = logging.getLogger(__name__)


@pytest.mark.vm
def test_vm_exists(
    malcolm_vm_info,
):
    """test_vm_exists

    Check that the VM in which the Malcolm instance is running is exists and has an IP address.

    Args:
        malcolm_vm_info (dict): information relating to the Malcolm instance (see MalcolmVM.Info())
    """
    LOGGER.debug(malcolm_vm_info)
    assert isinstance(malcolm_vm_info, dict) and malcolm_vm_info.get("ip", None)


@pytest.mark.mapi
def test_ping(
    malcolm_url,
    malcolm_http_auth,
):
    """test_ping

    Test the /mapi/ping API

    Args:
        malcolm_url (str): URL for connecting to the Malcolm instance
        malcolm_http_auth (HTTPBasicAuth): username and password for the Malcolm instance
    """
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
    """test_db_health

    Check the OpenSearch API and that the cluster's health returns "green" or "yellow"

    Args:
        malcolm_url (str): URL for connecting to the Malcolm instance
        database_objs (DatabaseObjs): object containing classes references for either the OpenSearch or Elasticsearch Python libraries
    """
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
