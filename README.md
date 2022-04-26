faat.userdb package
===================

This package provides a simple userdb stored in sqlite3.

It also offers a simple command line interface for managing users.


## Run the tests

This simple package doesn't require any third party packages.
From the root of this project, we don't even need to install it to run the tests.

```cmd
py -m unittest
```


## Future work

Some future things to consider...

*   Add more commands to the command line script.
    *   cleanup: delete old apikeys and invitations
    *   revoke-role: delete a role from a user
*   Schema management and migration
    *   add table and record to track the current schema version.
    *   add init command to initialize a new db
    *   add upgrade command to migrate the schema
    *   raise error when connecting to wrong schema version
*   Add support for TOTP codes
*   If we increase the hash strength, update password hashes for existing folks as they log in.
