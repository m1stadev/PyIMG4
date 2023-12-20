from importlib.metadata import version

from ._parser import *  # noqa: F403
from ._types import *  # noqa: F403
from .errors import *  # noqa: F403

__version__ = version(__package__)
