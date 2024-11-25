"""
malcolm-test serves to run an instance of Malcolm (https://idaholab.github.io/Malcolm/)
and verify the results of system tests executed against it.

This package contains the following modules:
- maltest: contains the CLI interface and high-level execution logic
- utils: contains classes used for managing and interfacing with Malcolm VM
"""

# -*- coding: utf-8 -*-

from importlib.metadata import version, PackageNotFoundError
from maltest.utils import MALTEST_PROJECT_NAME

try:
    __version__ = version(MALTEST_PROJECT_NAME)
except PackageNotFoundError:
    __version__ = None

__all__ = ["main"]

from .maltest import main
