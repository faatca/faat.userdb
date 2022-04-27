import argparse
import logging
import json
from pathlib import Path
import sys
from .core import connect

log = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(description="User database management tool")

    subparsers = parser.add_subparsers(dest="command", help="the command to execute")
    subparsers.required = True

    parent_parser = argparse.ArgumentParser(add_help=False)
    parent_parser.add_argument("-v", "--verbose", action="store_true", help="show debug messages")
    parent_parser.add_argument("target", type=Path, help="path to user database")

    add_user_parser = subparsers.add_parser(
        "add-user",
        description="Adds a user",
        help="adds a user",
        parents=[parent_parser],
    )
    add_user_parser.add_argument("username")
    add_user_parser.add_argument("password")
    add_user_parser.set_defaults(func=do_add_user)

    invite_parser = subparsers.add_parser(
        "invite",
        description="Creates an invitation for a new user",
        help="creates an invitation for a new user",
        parents=[parent_parser],
    )
    invite_parser.set_defaults(func=do_invite)

    revoke_invite_parser = subparsers.add_parser(
        "revoke-invite",
        description="Revokes an invitation for a new user",
        help="revokes an invitation for a new user",
        parents=[parent_parser],
    )
    revoke_invite_parser.add_argument("token")
    revoke_invite_parser.set_defaults(func=do_revoke_invite)

    lock_user_parser = subparsers.add_parser(
        "lock-user",
        description="Locks a user",
        help="locks a user",
        parents=[parent_parser],
    )
    lock_user_parser.add_argument("username")
    lock_user_parser.set_defaults(func=do_lock_user)

    unlock_user_parser = subparsers.add_parser(
        "unlock-user",
        description="Unlocks a user",
        help="unlocks a user",
        parents=[parent_parser],
    )
    unlock_user_parser.add_argument("username")
    unlock_user_parser.set_defaults(func=do_unlock_user)

    add_role_parser = subparsers.add_parser(
        "add-role",
        description="Adds a role",
        help="adds a role",
        parents=[parent_parser],
    )
    add_role_parser.add_argument("username")
    add_role_parser.add_argument("role")
    add_role_parser.set_defaults(func=do_add_role)

    clean_parser = subparsers.add_parser(
        "clean",
        description="Cleans out old entries from db",
        help="cleans out old entries from db",
        parents=[parent_parser],
    )
    clean_parser.add_argument(
        "--days", type=check_positive, default="7", help="the number of days to keep for history"
    )
    clean_parser.set_defaults(func=do_clean)

    list_users_parser = subparsers.add_parser(
        "list-users",
        description="Lists the users",
        help="lists users",
        parents=[parent_parser],
    )
    list_users_parser.set_defaults(func=do_list_users)

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-8s %(name)s %(message)s",
    )

    try:
        result = args.func(args)
    except Exception:
        log.exception("Unexpected error encountered")
        sys.exit(3)

    if result:
        sys.exit(int(result))


def do_add_user(args):
    with connect(args.target) as db:
        db.add_user(args.username, args.password)


def do_invite(args):
    with connect(args.target) as db:
        user_id, token = db.create_new_user_invitation()
    print("Token:", token)


def do_revoke_invite(args):
    with connect(args.target) as db:
        db.revoke_invitation(args.token)


def do_lock_user(args):
    with connect(args.target) as db:
        id = db.get_user_id(args.username)
        db.lock_user(id)


def do_unlock_user(args):
    with connect(args.target) as db:
        id = db.get_user_id(args.username)
        db.unlock_user(id)


def do_add_role(args):
    with connect(args.target) as db:
        id = db.get_user_id(args.username)
        db.add_role(id, args.role)


def do_clean(args):
    with connect(args.target) as db:
        db.clean(args.days)


def do_list_users(args):
    with connect(args.target) as db:
        users = list(db.find_users())
        print(json.dumps(users, indent=2))


def check_positive(value):
    ivalue = int(value)
    if ivalue < 0:
        raise argparse.ArgumentTypeError(f"{ivalue} is less than zero")
    return ivalue


if __name__ == "__main__":
    main()
