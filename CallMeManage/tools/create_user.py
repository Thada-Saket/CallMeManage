""" |======= Create a website account from the command line =======|

    .venv/bin/python tools/create_user.py             (or: sudo callmemanage user add)
    .venv/bin/python tools/create_user.py --if-none   only when no account exists yet (installer)

For the first account (or any account) when email/Google sign-up is not set up.
Uses the same rules as the website: username 5-32 characters, account password
policy (8-256, lower, upper, number, special) and the same create_user() code.
The password is typed twice and never echoed or logged.
"""

import argparse
import asyncio
import getpass
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from pydantic import ValidationError  # noqa: E402
from sqlalchemy import func  # noqa: E402
from sqlmodel import select  # noqa: E402

from backend.core.account_password_policy import ACCOUNT_PASSWORD_POLICY_MESSAGE  # noqa: E402
from backend.core.connect_database import AsyncSessionFactory, engine  # noqa: E402
from backend.crud.web_crud.crud_user import create_user  # noqa: E402
from backend.model.models import User_Table  # noqa: E402
from backend.schema.user_schema import UserCreate  # noqa: E402


ATTEMPTS = 3


def ask_once() -> UserCreate | None:
    username = input("Username (5-32 characters): ").strip()
    email = input("Email: ").strip()
    print(ACCOUNT_PASSWORD_POLICY_MESSAGE)
    password = getpass.getpass("Password: ")
    if getpass.getpass("Confirm password: ") != password:
        print("Passwords do not match - try again\n")
        return None
    try:
        return UserCreate(usr_name=username, usr_email=email, usr_passwd=password)
    except ValidationError as exc:
        reasons = "; ".join(f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors())
        print(f"Not accepted - {reasons}\n")
        return None


async def count_users() -> int:
    async with AsyncSessionFactory() as session:
        return (await session.exec(select(func.count()).select_from(User_Table))).one()


async def main(if_none: bool) -> None:
    try:
        if if_none and await count_users() > 0:
            print("An account already exists - skipped (add more with: sudo callmemanage user add)")
            return
        for _ in range(ATTEMPTS):
            user_create = ask_once()
            if user_create is None:
                continue
            async with AsyncSessionFactory() as session:
                # the address was typed by the operator on the server, so it counts as verified
                user = await create_user(session, user_create, email_verified_at=datetime.now(timezone.utc))
            if user is None:
                print("That username or email already has an account - try again\n")
                continue
            print(f"Created account '{user.usr_name}'. Sign in on the website with this username or email.")
            return
        raise SystemExit("No account was created")
    finally:
        await engine.dispose()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create a CallMe Manage website account")
    parser.add_argument("--if-none", action="store_true", help="do nothing when an account already exists")
    asyncio.run(main(parser.parse_args().if_none))
