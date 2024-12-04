import requests
from bs4 import BeautifulSoup


def test_malcolm_local_account_management(
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
