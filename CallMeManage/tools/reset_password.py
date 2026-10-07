""" |======= Set a new password for a website account =======|

    .venv/bin/python tools/reset_password.py <username or email>   (or: sudo callmemanage user passwd <name>)

For a user who forgot the password while email (password reset by code) is switched off.
Uses the same password policy and update as the website's reset flow: every session of
that user is signed out. The password is typed twice and never echoed or logged.
"""

import asyncio
import getpass
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from backend.core.account_password_policy import ACCOUNT_PASSWORD_POLICY_MESSAGE  # noqa: E402
from backend.core.connect_database import AsyncSessionFactory, engine  # noqa: E402
from backend.crud.web_crud.crud_user import (  # noqa: E402
    get_user_by_email_casefold,
    get_user_by_username,
    update_user_password,
)


async def main(identifier: str) -> None:
    try:
        async with AsyncSessionFactory() as session:
            user = await get_user_by_email_casefold(session, identifier) if "@" in identifier else None
            user = user or await get_user_by_username(session, identifier)
            if user is None:
                raise SystemExit(f"No account '{identifier}'")
            print(f"New password for '{user.usr_name}'")
            print(ACCOUNT_PASSWORD_POLICY_MESSAGE)
            password = getpass.getpass("Password: ")
            if getpass.getpass("Confirm password: ") != password:
                raise SystemExit("Passwords do not match - nothing was changed")
            try:
                await update_user_password(session, user, password)
            except ValueError as exc:
                raise SystemExit(f"Not changed - {exc}") from None
    finally:
        await engine.dispose()
    print("Password changed. That user is signed out everywhere and signs in with the new password.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: reset_password.py <username or email>")
    asyncio.run(main(sys.argv[1].strip()))
