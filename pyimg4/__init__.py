from .errors import *
from ._parser import *
from ._types import *

try:
    from importlib.metadata import version
except ModuleNotFoundError:
    from importlib_metadata import version

__version__ = version(__package__)
