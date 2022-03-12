from base64 import b64encode, b64decode
from hashlib import scrypt
import os


def format_password_hash(password):
    if len(password) > 1024:
        raise ValueError("Password is too long")
    scrypt_n = 2 ** 14
    scrypt_r = 9
    scrypt_p = 1

    salt = os.urandom(16)
    h = scrypt(password.encode(), salt=salt, n=scrypt_n, r=scrypt_r, p=scrypt_p)
    return (
        f"sc${scrypt_n}-{scrypt_r}-{scrypt_p}${b64encode(salt).decode()}${b64encode(h).decode()}"
    )


def verify(password, password_hash):
    if not password_hash.startswith("sc$"):
        raise ValueError("Unknown hash format")
    _, params, salt, pw_h = password_hash.split("$")
    salt = b64decode(salt)
    pw_h = b64decode(pw_h)
    n, r, p = params.split("-")
    dklen = len(pw_h)
    h = scrypt(password.encode(), salt=salt, n=int(n), r=int(r), p=int(p), dklen=dklen)
    return h == pw_h
