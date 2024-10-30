from importlib.metadata import version, PackageNotFoundError

try:
    __version__ = version("malcolm-test")
except PackageNotFoundError:
    __version__ = None

__all__ = ["main", "MalcolmVM"]

from .malcolm_test import main, MalcolmVM
