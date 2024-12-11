"""
provides fixtures usable by all pytests in the system

See https://docs.pytest.org/en/stable/reference/fixtures.html#conftest-py-sharing-fixtures-across-multiple-files
"""

# -*- coding: utf-8 -*-

import pytest

from maltest.utils import (
    get_malcolm_vm_info,
    get_artifact_hash_map,
    get_malcolm_http_auth,
    get_malcolm_url,
    get_database_objs,
)


@pytest.fixture
def malcolm_vm_info():
    """
    malcolm_vm_info: fixture wrapping .utils.get_malcolm_vm_info

    Returns:
        see .utils.get_malcolm_vm_info
    """
    yield get_malcolm_vm_info()


@pytest.fixture
def artifact_hash_map():
    """
    artifact_hash_map: fixture wrapping .utils.get_artifact_hash_map

    Returns:
        see .utils.get_artifact_hash_map
    """
    yield get_artifact_hash_map()


@pytest.fixture
def malcolm_http_auth():
    """
    malcolm_http_auth: fixture wrapping .utils.get_malcolm_http_auth

    Returns:
        see .utils.get_malcolm_http_auth
    """
    yield get_malcolm_http_auth()


@pytest.fixture
def database_objs():
    """
    database_objs: fixture wrapping .utils.get_database_objs

    Returns:
        see .utils.get_database_objs
    """
    yield get_database_objs()


@pytest.fixture
def malcolm_url():
    """
    malcolm_url: fixture wrapping .utils.get_malcolm_url

    Returns:
        see .utils.get_malcolm_url
    """
    yield get_malcolm_url()
