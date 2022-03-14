import datetime
from hashlib import sha256
import secrets
import sqlite3
from . import pwhash


def connect(path):
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    (has_table,) = db.execute(
        "select count(name) from sqlite_master where type='table' and name = 'user'"
    )
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS user (
            id INTEGER PRIMARY KEY,
            added_date DATE,
            status TEXT
        );

        CREATE TABLE IF NOT EXISTS credential
        (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            username TEXT UNIQUE,
            password TEXT,
            FOREIGN KEY (user_id) REFERENCES user (id)
        );

        CREATE TABLE IF NOT EXISTS apikey
        (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            apikey TEXT UNIQUE,
            label TEXT,
            issued_date DATE,
            FOREIGN KEY (user_id) REFERENCES user (id)
        );

        CREATE TABLE IF NOT EXISTS role (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            role TEXT,
            UNIQUE (user_id, role),
            FOREIGN KEY (user_id) REFERENCES user (id)
        )
        """
    )
    return UserDB(db)


class UserDB:
    def __init__(self, db):
        self.db = db

    def add_user(self, username, password):
        try:
            with self.db:
                user_id = self.db.execute(
                    "INSERT INTO user (added_date, status) VALUES (?, ?)",
                    (datetime.datetime.utcnow().isoformat(), "active"),
                ).lastrowid
                self.db.execute(
                    "INSERT INTO credential (user_id, username, password) VALUES (?, ?, ?)",
                    (user_id, username, pwhash.format_password_hash(password)),
                )
                return user_id
        except sqlite3.IntegrityError:
            raise AlreadyExistsError

    def lock_user(self, user_id):
        self.db.execute("UPDATE user SET status = 'locked' WHERE user_id = ?", (user_id,))

    def get_user_id(self, username):
        user_row = self.db.execute(
            "SELECT user_id FROM credential where username = ?", (username,)
        ).fetchone()
        if not user_row:
            raise UnknownUserError
        return user_row["user_id"]

    def add_role(self, user_id, role):
        try:
            self.db.execute("INSERT INTO role (user_id, role) VALUES (?, ?)", (user_id, role))
        except sqlite3.IntegrityError:
            raise AlreadyExistsError

    def authenticate(self, username, password):
        row = self.db.execute(
            """
            SELECT u.status, c.user_id, c.password
            FROM credential c
            INNER JOIN user u on u.id = c.user_id
            WHERE c.username = ?
            """,
            (username,),
        ).fetchone()
        if not row:
            raise UnknownUserError
        if not pwhash.verify(password, row["password"]):
            raise InvalidPasswordError
        if row["status"] != "active":
            raise AuthenticationError
        return str(row["user_id"])

    def create_apikey(self, user_id, label=None):
        token = secrets.token_urlsafe()
        hashed_token = sha256(token.encode()).hexdigest()
        with self.db:

            self.db.execute(
                "INSERT INTO apikey (user_id, apikey, label, issued_date) VALUES (?, ?, ?, ?)",
                (
                    user_id,
                    hashed_token,
                    label,
                    datetime.datetime.utcnow().isoformat(),
                ),
            )
        return token

    def authenticate_apikey(self, apikey):
        hashed_token = sha256(apikey.encode()).hexdigest()
        row = self.db.execute(
            "SELECT user_id FROM apikey WHERE apikey = ?", (hashed_token,)
        ).fetchone()
        if not row:
            raise AuthenticationError
        return row["user_id"]

    def close(self):
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()


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
