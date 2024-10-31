# -*- coding: utf-8 -*-

import pytest
from maltest.utils import get_malcolm_vm_info
from requests.auth import HTTPBasicAuth


@pytest.fixture
def malcolm_vm_info():
    yield get_malcolm_vm_info()


@pytest.fixture
def malcolm_http_auth():
    if info := get_malcolm_vm_info():
        auth = HTTPBasicAuth(
            info.get('username', ''),
            info.get('password', ''),
        )
        yield auth
    else:
        yield None


@pytest.fixture
def malcolm_url():
    if info := get_malcolm_vm_info():
        yield f"https://{info.get('ip', '')}"
    else:
        yield 'http://localhost'
