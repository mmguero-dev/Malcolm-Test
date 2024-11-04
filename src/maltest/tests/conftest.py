# -*- coding: utf-8 -*-

import pytest
from maltest.utils import (
    get_malcolm_vm_info,
    get_pcap_hash_map,
    get_malcolm_http_auth,
    get_malcolm_url,
)


@pytest.fixture
def malcolm_vm_info():
    yield get_malcolm_vm_info()


@pytest.fixture
def pcap_hash_map():
    yield get_pcap_hash_map()


@pytest.fixture
def malcolm_http_auth():
    yield get_malcolm_http_auth()


@pytest.fixture
def malcolm_url():
    yield get_malcolm_url()
