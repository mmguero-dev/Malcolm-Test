import pytest
import mmguero
import requests
import logging
import petname
from datetime import datetime, timedelta, UTC

LOGGER = logging.getLogger(__name__)


@pytest.mark.mapi
def test_mapi_indices(
    malcolm_url,
    malcolm_http_auth,
):
    """test_mapi_indices

    Test the /mapi/indices API

    Args:
        malcolm_url (str): URL for connecting to the Malcolm instance
        malcolm_http_auth (HTTPBasicAuth): username and password for the Malcolm instance
    """
    response = requests.get(
        f"{malcolm_url}/mapi/indices",
        headers={"Content-Type": "application/json"},
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    indices = {item['index']: item for item in response.json().get('indices', [])}
    LOGGER.debug(indices)
    assert indices


@pytest.mark.mapi
def test_mapi_fields(
    malcolm_url,
    malcolm_http_auth,
):
    """test_mapi_fields

    Test the /mapi/fields API

    Args:
        malcolm_url (str): URL for connecting to the Malcolm instance
        malcolm_http_auth (HTTPBasicAuth): username and password for the Malcolm instance
    """
    response = requests.get(
        f"{malcolm_url}/mapi/fields",
        headers={"Content-Type": "application/json"},
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    fieldsResponse = response.json()
    LOGGER.debug(fieldsResponse)
    fieldsTotal = fieldsResponse.get("total", 0)
    assert fieldsTotal > 1000
    assert len(fieldsResponse.get("fields", [])) == fieldsTotal


@pytest.mark.mapi
def test_mapi_dashboard_export(
    malcolm_url,
    malcolm_http_auth,
):
    """test_mapi_dashboard_export

    Test the /mapi/dashboard-export API by exporting the "Overview" dashboard and checking its title

    Args:
        malcolm_url (str): URL for connecting to the Malcolm instance
        malcolm_http_auth (HTTPBasicAuth): username and password for the Malcolm instance
    """
    response = requests.get(
        f"{malcolm_url}/mapi/dashboard-export/0ad3d7c2-3441-485e-9dfe-dbb22e84e576",
        headers={"Content-Type": "application/json"},
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    dashboardData = response.json()
    LOGGER.debug(dashboardData)
    assert dashboardData.get("objects", [])[0].get("attributes", {}).get("title", "") == "Overview"


@pytest.mark.mapi
def test_event_log_mapi(
    malcolm_http_auth,
    malcolm_url,
):
    """test_event_log_mapi

    Test the /mapi/event API to log an event via the loopback alert webhook

    Args:
        malcolm_http_auth (HTTPBasicAuth): username and password for the Malcolm instance
        malcolm_url (str): URL for connecting to the Malcolm instance
    """
    alert = {
        "alert": {
            "monitor": {"name": "Malcolm API Loopback Monitor"},
            "trigger": {"name": "Malcolm API Loopback Trigger", "severity": 4},
            "period": {
                "end": datetime.now(UTC).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z',
                "start": (datetime.now(UTC) - timedelta(minutes=1)).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z',
            },
            "results": [
                {
                    "_shards": {"total": 5, "failed": 0, "successful": 5, "skipped": 0},
                    "hits": {"hits": [], "total": {"value": 697, "relation": "eq"}, "max_score": None},
                    "took": 1,
                    "timed_out": False,
                }
            ],
            "body": "",
            "alert": petname.Generate(),
            "error": "",
        }
    }

    response = requests.post(
        f"{malcolm_url}/mapi/event",
        headers={"Content-Type": "application/json"},
        json=alert,
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    responseData = response.json()
    LOGGER.debug(responseData)
    assert mmguero.DeepGet(responseData, ['result', '_id'], '')
    assert mmguero.DeepGet(responseData, ['result', '_index'], '')
    assert mmguero.DeepGet(responseData, ['result', 'result'], '') in ['created', 'updated']
