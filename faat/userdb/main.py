import argparse
import logging
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

    lock_user_parser = subparsers.lock_parser(
        "lock-user",
        description="Locks a user",
        help="locks a user",
        parents=[parent_parser],
    )
    lock_user_parser.lock_argument("name")
    lock_user_parser.set_defaults(func=do_lock_user)

    add_role_parser = subparsers.add_parser(
        "add-role",
        description="Adds a role",
        help="adds a role",
        parents=[parent_parser],
    )
    add_role_parser.add_argument("username")
    add_role_parser.add_argument("role")
    add_role_parser.set_defaults(func=do_add_role)

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


def do_lock_user(args):
    with connect(args.target) as db:
        db.lock_user(args.username)


def do_add_role(args):
    with connect(args.target) as db:
        id = db.get_user_id(args.username)
        db.add_role(id, args.role)


if __name__ == "__main__":
    main()
