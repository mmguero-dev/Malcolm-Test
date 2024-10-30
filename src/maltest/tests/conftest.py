# -*- coding: utf-8 -*-

import pytest
from maltest.utils import get_malcolm_vm_info


@pytest.fixture
def malcolm_vm_info():
    return get_malcolm_vm_info()
