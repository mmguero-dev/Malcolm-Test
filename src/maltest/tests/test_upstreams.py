import pytest
import requests
from bs4 import BeautifulSoup
import logging
import re

LOGGER = logging.getLogger(__name__)


def DebugSoupLine(soup):
    return "\n".join([re.sub(r'\s+', ' ', line.strip()) for line in soup.get_text().splitlines() if line.strip()])


@pytest.mark.webui
def test_local_account_management_page_exists(
    malcolm_url,
    malcolm_http_auth,
):
    """test_local_account_management_page_exists

    Test that the local account management authentication page is served up

    Args:
        malcolm_url (str): URL for connecting to the Malcolm instance
        malcolm_http_auth (HTTPBasicAuth): username and password for the Malcolm instance
    """
    response = requests.get(
        f"{malcolm_url}/auth/",
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    soup = BeautifulSoup(response.content, 'html.parser')
    LOGGER.debug(DebugSoupLine(soup))
    assert soup.title.string == "Malcolm User Management"


@pytest.mark.webui
def test_upload_page_exists(
    malcolm_url,
    malcolm_http_auth,
):
    """test_upload_page_exists

    Test that the PCAP upload page is served up

    Args:
        malcolm_url (str): URL for connecting to the Malcolm instance
        malcolm_http_auth (HTTPBasicAuth): username and password for the Malcolm instance
    """
    response = requests.get(
        f"{malcolm_url}/upload/",
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    soup = BeautifulSoup(response.content, 'html.parser')
    LOGGER.debug(DebugSoupLine(soup))
    assert soup.title.string == "File Upload"


@pytest.mark.webui
def test_landing_page_exists(
    malcolm_url,
    malcolm_http_auth,
):
    """test_landing_page_exists

    Test that the Malcolm landing page is served up

    Args:
        malcolm_url (str): URL for connecting to the Malcolm instance
        malcolm_http_auth (HTTPBasicAuth): username and password for the Malcolm instance
    """
    response = requests.get(
        f"{malcolm_url}/",
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    soup = BeautifulSoup(response.content, 'html.parser')
    LOGGER.debug(DebugSoupLine(soup))
    assert "Read the Malcolm user guide" in soup.get_text()


@pytest.mark.webui
def test_documentation_exists(
    malcolm_url,
    malcolm_http_auth,
):
    """test_documentation_exists

    Test that the Malcolm documentation page is served up

    Args:
        malcolm_url (str): URL for connecting to the Malcolm instance
        malcolm_http_auth (HTTPBasicAuth): username and password for the Malcolm instance
    """
    response = requests.get(
        f"{malcolm_url}/readme/",
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    soup = BeautifulSoup(response.content, 'html.parser')
    LOGGER.debug(DebugSoupLine(soup))
    assert (
        "A powerful, easily deployable network traffic analysis tool suite for network security monitoring"
        in soup.get_text()
    )


@pytest.mark.dashboards
@pytest.mark.webui
def test_dashboards_exists(
    malcolm_url,
    malcolm_http_auth,
):
    """test_dashboards_exists

    Test that the Malcolm OpenSearch Dashboards UI is served up

    Args:
        malcolm_url (str): URL for connecting to the Malcolm instance
        malcolm_http_auth (HTTPBasicAuth): username and password for the Malcolm instance
    """
    response = requests.get(
        f"{malcolm_url}/dashboards/",
        headers={"osd-xsrf": "anything"},
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    soup = BeautifulSoup(response.content, 'html.parser')
    LOGGER.debug(DebugSoupLine(soup))
    assert soup.title.string == "Malcolm Dashboards"


@pytest.mark.dashboards
@pytest.mark.webui
def test_dashboards_maps_exists(
    malcolm_url,
    malcolm_http_auth,
):
    """test_dashboards_maps_exists

    Test that the Malcolm OpenSearch Dashboards offline map geojson file is served up

    Args:
        malcolm_url (str): URL for connecting to the Malcolm instance
        malcolm_http_auth (HTTPBasicAuth): username and password for the Malcolm instance
    """
    response = requests.get(
        f"{malcolm_url}/world.geojson",
        headers={"Content-Type": "application/json"},
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    geo = response.json()
    LOGGER.debug(geo)
    assert (geo.get('type', '') == 'FeatureCollection') and (geo.get('features', []))


@pytest.mark.netbox
@pytest.mark.webui
def test_netbox_exists(
    malcolm_url,
    malcolm_http_auth,
):
    """test_netbox_exists

    Test that the NetBox UI is served up

    Args:
        malcolm_url (str): URL for connecting to the Malcolm instance
        malcolm_http_auth (HTTPBasicAuth): username and password for the Malcolm instance
    """
    response = requests.get(
        f"{malcolm_url}/netbox/",
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    soup = BeautifulSoup(response.content, 'html.parser')
    LOGGER.debug(DebugSoupLine(soup))
    assert 'NetBox' in soup.title.string


@pytest.mark.netbox
@pytest.mark.webui
def test_netbox_health_plugin(
    malcolm_url,
    malcolm_http_auth,
):
    """test_netbox_health_plugin

    Check the accessibility and result of the NetBox health check plugin

    Args:
        malcolm_url (str): URL for connecting to the Malcolm instance
        malcolm_http_auth (HTTPBasicAuth): username and password for the Malcolm instance
    """
    response = requests.get(
        f"{malcolm_url}/netbox/plugins/netbox_healthcheck_plugin/healthcheck/?format=json",
        headers={"Content-Type": "application/json"},
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    health = response.json()
    LOGGER.debug(health)
    assert health and all([v == "working" for k, v in health.items()])


@pytest.mark.arkime
@pytest.mark.webui
def test_arkime_exists(
    malcolm_url,
    malcolm_http_auth,
):
    """test_arkime_exists

    Test that the Arkime UI is served up

    Args:
        malcolm_url (str): URL for connecting to the Malcolm instance
        malcolm_http_auth (HTTPBasicAuth): username and password for the Malcolm instance
    """
    response = requests.get(
        f"{malcolm_url}/arkime/",
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    soup = BeautifulSoup(response.content, 'html.parser')
    LOGGER.debug(DebugSoupLine(soup))
    assert soup.title.string == "Arkime"


@pytest.mark.webui
def test_cyberchef_exists(
    malcolm_url,
    malcolm_http_auth,
):
    """test_cyberchef_exists

    Test that the CyberChef UI is served up

    Args:
        malcolm_url (str): URL for connecting to the Malcolm instance
        malcolm_http_auth (HTTPBasicAuth): username and password for the Malcolm instance
    """
    response = requests.get(
        f"{malcolm_url}/arkime/cyberchef/",
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    soup = BeautifulSoup(response.content, 'html.parser')
    LOGGER.debug(DebugSoupLine(soup))
    assert soup.title.string == "CyberChef"


@pytest.mark.carving
@pytest.mark.webui
def test_extracted_files_exists(
    malcolm_url,
    malcolm_http_auth,
):
    """test_extracted_files_exists

    Check the extracted files download UI is served up

    Args:
        malcolm_url (str): URL for connecting to the Malcolm instance
        malcolm_http_auth (HTTPBasicAuth): username and password for the Malcolm instance
    """
    response = requests.get(
        f"{malcolm_url}/extracted-files/",
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    soup = BeautifulSoup(response.content, 'html.parser')
    LOGGER.debug(DebugSoupLine(soup))
    assert "Directory listing for" in soup.get_text()
