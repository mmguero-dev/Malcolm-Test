# -*- coding: utf-8 -*-

import pytest
from maltest.utils import get_malcolm_vm_info
from requests.auth import HTTPBasicAuth


@pytest.fixture
def malcolm_vm_info():
    return get_malcolm_vm_info()


@pytest.fixture
def malcolm_http_auth():
    if info := get_malcolm_vm_info():
        return HTTPBasicAuth(
            info.get('password', ''),
            info.get('username', ''),
        )
    else:
        return HTTPBasicAuth('', '')


@pytest.fixture
def malcolm_url():
    if info := get_malcolm_vm_info():
        f"https://{info.get('ip', '')}"
    else:
        return 'http://localhost'
