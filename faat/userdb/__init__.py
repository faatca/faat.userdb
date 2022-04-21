__version__ = "0.0.1"

from .core import connect
from .errors import (
    Error,
    AlreadyExistsError,
    AuthenticationError,
    UnknownUserError,
    InvalidPasswordError,
    ExpiryError,
)
