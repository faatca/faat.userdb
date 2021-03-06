import datetime
from hashlib import sha256
import logging
import secrets
import sqlite3

from . import pwhash
from . import errors

log = logging.getLogger(__name__)


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
            revoked DATE,
            FOREIGN KEY (user_id) REFERENCES user (id)
        );

        CREATE TABLE IF NOT EXISTS role (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            role TEXT,
            UNIQUE (user_id, role),
            FOREIGN KEY (user_id) REFERENCES user (id)
        );

        CREATE TABLE IF NOT EXISTS reset_request (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            hash TEXT,
            issued_date DATE,
            expiry_date DATE,
            redeemed DATE,
            revoked DATE,
            FOREIGN KEY (user_id) REFERENCES user (id)
        )
        """
    )
    return UserDB(db)


class UserDB:
    def __init__(self, db):
        self.db = db

    def find_users(self):
        user_rows = self.db.execute("SELECT id, added_date, status FROM user")
        for user_row in user_rows:
            credential_rows = self.db.execute(
                "SELECT username, password FROM credential WHERE user_id = ?", (user_row["id"],)
            )
            usernames = [r["username"] for r in credential_rows]

            apikey_rows = self.db.execute(
                "SELECT label FROM apikey WHERE user_id = ? AND revoked IS NULL", (user_row["id"],)
            )
            apikeys = [r["label"] for r in apikey_rows]

            role_rows = self.db.execute(
                "SELECT role FROM role WHERE user_id = ?", (user_row["id"],)
            )
            roles = [r["role"] for r in role_rows]

            reset_rows = self.db.execute(
                """
                SELECT count(*) AS c
                FROM reset_request
                WHERE
                  user_id = ? AND
                  redeemed IS NULL AND
                  revoked IS NULL AND
                  expiry_date > ?
                """,
                (user_row["id"], datetime.datetime.utcnow()),
            )
            reset_row_count = sum(row["c"] for row in reset_rows)

            yield {
                "id": user_row["id"],
                "usernames": usernames,
                "apikeys": apikeys,
                "resets": reset_row_count,
                "status": user_row["status"],
                "roles": roles,
            }

    def clean(self, retention_days=7):
        cutoff = datetime.datetime.utcnow() - datetime.timedelta(days=retention_days)
        log.debug(f"Cleaning expired entries before {retention_days} days: {cutoff}")
        with self.db:
            cursor = self.db.execute(
                """
                DELETE FROM apikey WHERE revoked < ?
                """,
                (cutoff,),
            )
            log.debug(f"Cleaned {cursor.rowcount} revoked API keys")

            cursor = self.db.execute(
                """
                DELETE FROM reset_request
                WHERE redeemed < ? OR revoked < ? OR expiry_date < ?
                """,
                (cutoff, cutoff, cutoff),
            )
            log.debug(f"Cleaned {cursor.rowcount} invitations or password reset requests")

            with self.db:
                user_rows = self.db.execute(
                    """
                    SELECT id FROM user
                    WHERE id not in (
                        SELECT user_id FROM credential
                        UNION
                        SELECT user_id FROM apikey
                        UNION
                        SELECT user_id FROM reset_request
                    )
                    """
                )
                param_rows = list(user_rows)
                log.debug(f"Cleaning {len(param_rows)} users")
                self.db.executemany("DELETE FROM role WHERE user_id = ?", param_rows)
                self.db.executemany("DELETE FROM user WHERE id = ?", param_rows)

    def add_user(self, username, password):
        try:
            log.debug(f"Adding new user: {username}")
            with self.db:
                user_id = self.db.execute(
                    "INSERT INTO user (added_date, status) VALUES (?, ?)",
                    (datetime.datetime.utcnow().isoformat(), ACTIVE_STATUS),
                ).lastrowid
                self.db.execute(
                    "INSERT INTO credential (user_id, username, password) VALUES (?, ?, ?)",
                    (user_id, username, pwhash.format_password_hash(password)),
                )
                return user_id
        except sqlite3.IntegrityError:
            log.debug(f"Failed to add user: {username}")
            raise errors.AlreadyExistsError

    def create_new_user_invitation(self):
        try:
            log.debug("Creating new invitation")
            with self.db:
                user_id = self.db.execute(
                    "INSERT INTO user (added_date, status) VALUES (?, ?)",
                    (datetime.datetime.utcnow().isoformat(), ACTIVE_STATUS),
                ).lastrowid

                token = secrets.token_urlsafe()
                hashed_token = sha256(token.encode()).hexdigest()

                self.db.execute(
                    "INSERT INTO reset_request (user_id, hash, issued_date, expiry_date) VALUES (?, ?, ?, ?)",
                    (
                        user_id,
                        hashed_token,
                        datetime.datetime.utcnow().isoformat(),
                        (datetime.datetime.utcnow() + datetime.timedelta(days=7)).isoformat(),
                    ),
                )
            log.debug(f"Created invitation for new user: {user_id}")
            return user_id, token
        except sqlite3.IntegrityError:
            raise errors.AlreadyExistsError

    def redeem_invitation(self, token, username, password):
        log.debug(f"Trying to redeem invitation as {username}")
        hashed_token = sha256(token.encode()).hexdigest()
        with self.db:
            row = self.db.execute(
                """
                SELECT u.id, u.status, r.user_id, r.expiry_date, r.redeemed
                FROM user u
                INNER JOIN reset_request r on u.id == r.user_id
                WHERE hash = ?
                """,
                (hashed_token,),
            ).fetchone()
            if not row:
                raise errors.UnknownUserError
            if row["redeemed"] or row["expiry_date"] < datetime.datetime.utcnow().isoformat():
                raise errors.ExpiryError
            if row["status"] != ACTIVE_STATUS:
                raise errors.AuthenticationError

            log.debug("Found invitation, adding credentials")
            self.db.execute(
                "INSERT INTO credential (user_id, username, password) VALUES (?, ?, ?)",
                (row["user_id"], username, pwhash.format_password_hash(password)),
            )
            self.db.execute(
                "UPDATE reset_request SET redeemed = ? WHERE id = ?",
                (datetime.datetime.utcnow(), row["id"]),
            )

    def create_password_reset(self, user_id):
        log.debug(f"Issuing password reset for user {user_id}")
        token = secrets.token_urlsafe()
        hashed_token = sha256(token.encode()).hexdigest()
        with self.db:
            self.db.execute(
                "INSERT INTO reset_request (user_id, hash, issued_date, expiry_date) VALUES (?, ?, ?, ?)",
                (
                    user_id,
                    hashed_token,
                    datetime.datetime.utcnow().isoformat(),
                    datetime.datetime.utcnow() + datetime.timedelta(days=7),
                ),
            )
        return token

    def revoke_invitation(self, token):
        hashed_token = sha256(token.encode()).hexdigest()
        with self.db:
            cursor = self.db.execute(
                """
                UPDATE reset_request
                SET revoked = ?
                WHERE hash = ? AND revoked IS NULL AND redeemed IS NULL
                """,
                (datetime.datetime.utcnow(), hashed_token),
            )
            if cursor.rowcount:
                log.debug("Revoked invitation")
            else:
                log.debug("No invitation found to revoke")

    def revoke_password_resets(self, user_id):
        with self.db:
            cursor = self.db.execute(
                """
                UPDATE reset_request
                SET revoked = ?
                WHERE user_id = ? AND revoked IS NULL AND redeemed IS NULL
                """,
                (datetime.datetime.utcnow(), user_id),
            )
            if cursor.rowcount:
                log.debug("Revoked password reset")
            else:
                log.debug("No password reset found to revoke")

    def redeem_password_reset(self, token, password):
        hashed_token = sha256(token.encode()).hexdigest()
        hashed_password = pwhash.format_password_hash(password)
        with self.db:
            row = self.db.execute(
                """
                SELECT u.id, u.status, r.revoked, r.expiry_date, r.redeemed
                FROM user u
                INNER JOIN reset_request r on u.id = r.user_id
                WHERE r.hash = ?
                """,
                (hashed_token,),
            ).fetchone()
            if not row:
                raise errors.AuthenticationError
            if row["status"] != ACTIVE_STATUS:
                raise errors.AuthenticationError
            if row["revoked"] or row["expiry_date"] < datetime.datetime.utcnow().isoformat():
                raise errors.ExpiryError
            self.db.execute(
                "UPDATE credential set password = ? where user_id = ?",
                (hashed_password, row["id"]),
            )

    def lock_user(self, user_id):
        log.debug(f"Locking access for user {user_id}")
        with self.db:
            self.db.execute("UPDATE user SET status = 'locked' WHERE id = ?", (user_id,))

    def unlock_user(self, user_id):
        log.debug(f"Unlocking access for user {user_id}")
        with self.db:
            self.db.execute("UPDATE user SET status = 'active' WHERE id = ?", (user_id,))

    def get_user_id(self, username):
        user_row = self.db.execute(
            "SELECT user_id FROM credential where username = ?", (username,)
        ).fetchone()
        if not user_row:
            raise errors.UnknownUserError
        return user_row["user_id"]

    def add_role(self, user_id, role):
        log.debug(f"Adding {role} to user {user_id}")
        try:
            with self.db:
                self.db.execute("INSERT INTO role (user_id, role) VALUES (?, ?)", (user_id, role))
        except sqlite3.IntegrityError:
            raise errors.AlreadyExistsError

    def revoke_role(self, user_id, role):
        log.debug(f"Removing {role} role from {user_id}")
        with self.db:
            self.db.execute("DELETE FROM role WHERE user_id = ? and role = ?", (user_id, role))

    def get_roles(self, user_id):
        sql = "SELECT role FROM role WHERE user_id = ?"
        return [row["role"] for row in self.db.execute(sql, (user_id,))]

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
            raise errors.UnknownUserError
        if not password:
            raise errors.InvalidPasswordError
        if not pwhash.verify(password, row["password"]):
            raise errors.InvalidPasswordError
        if row["status"] != ACTIVE_STATUS:
            raise errors.AuthenticationError
        return row["user_id"]

    def create_apikey(self, user_id, label=None):
        token = secrets.token_urlsafe()
        hashed_token = sha256(token.encode()).hexdigest()
        with self.db:
            log.debug(f"Issuing API key {label} for user {user_id}")
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

    def revoke_apikey(self, user_id, label):
        log.debug(f"Revoking {label} apikey for user {user_id}")
        with self.db:
            self.db.execute(
                """
                UPDATE apikey
                SET revoked = ?
                WHERE user_id = ? and label = ? and revoked IS NULL
                """,
                (datetime.datetime.utcnow().isoformat(), user_id, label),
            )

    def authenticate_apikey(self, apikey):
        if not apikey:
            raise errors.AuthenticationError
        hashed_token = sha256(apikey.encode()).hexdigest()
        row = self.db.execute(
            """
            SELECT u.id, u.status, a.revoked
            FROM user u
            INNER JOIN apikey a on a.user_id = u.id
            WHERE apikey = ?
            """,
            (hashed_token,),
        ).fetchone()
        if not row:
            raise errors.AuthenticationError
        if row["status"] != ACTIVE_STATUS or row["revoked"]:
            raise errors.AuthenticationError
        return row["id"]

    def close(self):
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()


ACTIVE_STATUS = "active"
