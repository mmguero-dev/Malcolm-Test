import pytest
import requests
from bs4 import BeautifulSoup


@pytest.mark.webui
def test_local_account_management_page_exists(
    malcolm_url,
    malcolm_http_auth,
):
    response = requests.get(
        f"{malcolm_url}/auth/",
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    soup = BeautifulSoup(response.content, 'html.parser')
    assert soup.title.string == "Malcolm User Management"


@pytest.mark.webui
def test_upload_page_exists(
    malcolm_url,
    malcolm_http_auth,
):
    response = requests.get(
        f"{malcolm_url}/upload/",
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    soup = BeautifulSoup(response.content, 'html.parser')
    assert soup.title.string == "File Upload"


@pytest.mark.webui
def test_landing_page_exists(
    malcolm_url,
    malcolm_http_auth,
):
    response = requests.get(
        f"{malcolm_url}/",
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    soup = BeautifulSoup(response.content, 'html.parser')
    assert "Read the Malcolm user guide" in soup.get_text()


@pytest.mark.webui
def test_documentation_exists(
    malcolm_url,
    malcolm_http_auth,
):
    response = requests.get(
        f"{malcolm_url}/readme/",
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    soup = BeautifulSoup(response.content, 'html.parser')
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
    response = requests.get(
        f"{malcolm_url}/dashboards/",
        headers={"osd-xsrf": "anything"},
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    soup = BeautifulSoup(response.content, 'html.parser')
    assert soup.title.string == "Malcolm Dashboards"


@pytest.mark.dashboards
@pytest.mark.webui
def test_dashboards_maps_exists(
    malcolm_url,
    malcolm_http_auth,
):
    response = requests.get(
        f"{malcolm_url}/world.geojson",
        headers={"Content-Type": "application/json"},
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    geo = response.json()
    assert (geo.get('type', '') == 'FeatureCollection') and (geo.get('features', []))


@pytest.mark.netbox
@pytest.mark.webui
def test_netbox_exists(
    malcolm_url,
    malcolm_http_auth,
):
    response = requests.get(
        f"{malcolm_url}/netbox/",
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    soup = BeautifulSoup(response.content, 'html.parser')
    assert 'NetBox' in soup.title.string


@pytest.mark.netbox
@pytest.mark.webui
def test_netbox_health_plugin(
    malcolm_url,
    malcolm_http_auth,
):
    response = requests.get(
        f"{malcolm_url}/netbox/plugins/netbox_healthcheck_plugin/healthcheck/?format=json",
        headers={"Content-Type": "application/json"},
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    health = response.json()
    assert health and all([v == "working" for k, v in health.items()])


@pytest.mark.arkime
@pytest.mark.webui
def test_arkime_exists(
    malcolm_url,
    malcolm_http_auth,
):
    response = requests.get(
        f"{malcolm_url}/arkime/",
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    soup = BeautifulSoup(response.content, 'html.parser')
    assert soup.title.string == "Arkime"


@pytest.mark.webui
def test_cyberchef_exists(
    malcolm_url,
    malcolm_http_auth,
):
    response = requests.get(
        f"{malcolm_url}/arkime/cyberchef/",
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    soup = BeautifulSoup(response.content, 'html.parser')
    assert soup.title.string == "CyberChef"


@pytest.mark.carving
@pytest.mark.webui
def test_extracted_files_exists(
    malcolm_url,
    malcolm_http_auth,
):
    response = requests.get(
        f"{malcolm_url}/extracted-files/",
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    soup = BeautifulSoup(response.content, 'html.parser')
    assert "Directory listing for" in soup.get_text()
