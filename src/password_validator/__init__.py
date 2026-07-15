"""
Entry point for the password_validator package.
A configurable password validation library that allows users to define custom rules and
criteria for password strength and security.
"""
from .version import (
    __title__,
    __version__,
    __author__,
    __description__
)


# Package metadata
VERSION = __version__

__all__ = [
    "__version__",
    "__title__",
    "__author__",
    "__description__",
    "VERSION",
]
