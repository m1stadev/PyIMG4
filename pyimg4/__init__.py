from importlib.metadata import version

from .errors import *
from .parser import *
from .types import *

__version__ = version(__package__)
