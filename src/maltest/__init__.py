from importlib.metadata import version, PackageNotFoundError
from maltest.utils import MALTEST_PROJECT_NAME

try:
    __version__ = version(MALTEST_PROJECT_NAME)
except PackageNotFoundError:
    __version__ = None

__all__ = ["main"]

from .maltest import main
