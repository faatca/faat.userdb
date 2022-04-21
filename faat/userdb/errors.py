class Error(Exception):
    pass


class AlreadyExistsError(Error):
    pass


class AuthenticationError(Error):
    pass


class UnknownUserError(AuthenticationError):
    pass


class InvalidPasswordError(AuthenticationError):
    pass


class ExpiryError(AuthenticationError):
    pass
