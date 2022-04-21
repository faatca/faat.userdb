from faat.userdb import connect
from faat.userdb import errors
import datetime
import unittest


class RegistrationTests(unittest.TestCase):
    def test_invite(self):
        db = connect(":memory:")
        user_id, invitation_token = db.create_new_user_invitation()
        db.redeem_invitation(invitation_token, "aaron", "secret-password")
        self.assertTrue(user_id)

    # TODO: X test revoked invitation

    def test_redeem_invitation_on_locked_account(self):
        db = connect(":memory:")
        user_id, invitation_token = db.create_new_user_invitation()
        db.lock_user(user_id)
        with self.assertRaises(errors.AuthenticationError):
            db.redeem_invitation(invitation_token, "aaron", "secret-password")

    def test_old_invite(self):
        db = connect(":memory:")
        user_id, invitation_token = db.create_new_user_invitation()
        expiry = datetime.datetime.utcnow() - datetime.timedelta(minutes=5)
        db.db.execute("update reset_request set expiry_date = ?", (expiry,))
        with self.assertRaises(errors.ExpiryError):
            db.redeem_invitation(invitation_token, "aaron", "secret-password")


class UserPasswordTests(unittest.TestCase):
    def setUp(self):
        self.db = connect(":memory:")
        self.user_id, invitation_token = self.db.create_new_user_invitation()
        self.username = "aaron"
        self.password = "secret-password"
        self.db.redeem_invitation(invitation_token, self.username, self.password)

    def test_authenticate_succeeds(self):
        user_id = self.db.authenticate(self.username, self.password)
        self.assertEqual(user_id, self.user_id)

    def test_authentication_fails_unknown(self):
        with self.assertRaises(errors.UnknownUserError):
            self.db.authenticate("anonymous", self.password)

        with self.assertRaises(errors.UnknownUserError):
            self.db.authenticate("anonymous", None)

    def test_authentication_fails_password(self):
        with self.assertRaises(errors.InvalidPasswordError):
            self.db.authenticate(self.username, None)
        with self.assertRaises(errors.InvalidPasswordError):
            self.db.authenticate(self.username, "")
        with self.assertRaises(errors.InvalidPasswordError):
            self.db.authenticate(self.username, "blargh")

    def test_authentication_fails_locked(self):
        self.db.lock_user(self.user_id)
        with self.assertRaises(errors.AuthenticationError):
            self.db.authenticate(self.username, self.password)

    def test_unlocked_user(self):
        self.db.lock_user(self.user_id)
        self.db.unlock_user(self.user_id)
        user_id = self.db.authenticate(self.username, self.password)
        self.assertEqual(user_id, self.user_id)

    def test_reset_password(self):
        reset_id = self.db.create_password_reset(self.user_id)
        new_password = "secret-password-2"
        self.db.redeem_password_reset(reset_id, new_password)
        with self.assertRaises(errors.InvalidPasswordError):
            self.db.authenticate(self.username, self.password)
        user_id = self.db.authenticate(self.username, new_password)
        self.assertEqual(user_id, self.user_id)

    def test_revoke_password_reset(self):
        reset_id = self.db.create_password_reset(self.user_id)
        self.db.revoke_password_resets(self.user_id)
        with self.assertRaises(errors.ExpiryError):
            self.db.redeem_password_reset(reset_id, "blargh")

    def test_reset_password_on_locked_account(self):
        reset_id = self.db.create_password_reset(self.user_id)
        self.db.lock_user(self.user_id)
        with self.assertRaises(errors.AuthenticationError):
            self.db.redeem_password_reset(reset_id, "blargh")


class ApiKeyTests(unittest.TestCase):
    def setUp(self):
        self.db = connect(":memory:")
        self.user_id, invitation_token = self.db.create_new_user_invitation()
        self.username = "aaron"
        self.password = "secret-password"
        self.db.redeem_invitation(invitation_token, self.username, self.password)
        self.label = "Test API"
        self.apikey = self.db.create_apikey(self.user_id, label=self.label)

    def test_authenticate_succeeds(self):
        new_user_id = self.db.authenticate_apikey(self.apikey)
        self.assertEqual(new_user_id, self.user_id)

    def test_revoke_api_key(self):
        self.db.revoke_apikey(self.user_id, self.label)
        with self.assertRaises(errors.AuthenticationError):
            self.db.authenticate_apikey(self.apikey)

    def test_authentication_fails_unknown(self):
        with self.assertRaises(errors.AuthenticationError):
            self.db.authenticate_apikey(self.password)

        with self.assertRaises(errors.AuthenticationError):
            self.db.authenticate_apikey(None)

        with self.assertRaises(errors.AuthenticationError):
            self.db.authenticate_apikey("")

    def test_authentication_fails_locked(self):
        self.db.lock_user(self.user_id)
        with self.assertRaises(errors.AuthenticationError):
            self.db.authenticate_apikey(self.apikey)


class RoleTests(unittest.TestCase):
    def setUp(self):
        self.db = connect(":memory:")
        self.user_id, invitation_token = self.db.create_new_user_invitation()

    def test_add_roles(self):
        self.db.add_role(self.user_id, "admin")
        self.db.add_role(self.user_id, "sa")
        roles = set(self.db.get_roles(self.user_id))
        self.assertEqual(roles, {"admin", "sa"})

    def test_add_duplicate_roles(self):
        self.db.add_role(self.user_id, "admin")
        with self.assertRaises(errors.AlreadyExistsError):
            self.db.add_role(self.user_id, "admin")

    def test_revoke_role(self):
        self.db.add_role(self.user_id, "admin")
        self.db.revoke_role(self.user_id, "admin")
        roles = self.db.get_roles(self.user_id)
        self.assertNotIn("admin", roles)

    def test_revoke_unknown_role(self):
        self.db.add_role(self.user_id, "sa")
        self.db.revoke_role(self.user_id, "admin")
        roles = self.db.get_roles(self.user_id)
        self.assertEqual(roles, ["sa"])
