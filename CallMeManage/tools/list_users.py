""" |======= List website accounts =======|

    .venv/bin/python tools/list_users.py             (or: sudo callmemanage user list)

Read only. Shows who can sign in to the website and how many sites each one owns or
has joined. Password hashes, Google IDs and tokens are never printed.
"""

import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sqlmodel import select  # noqa: E402

from backend.core.connect_database import AsyncSessionFactory, engine  # noqa: E402
from backend.crud.web_crud.crud_site import count_joined_site_memberships, count_owned_sites  # noqa: E402
from backend.model.models import User_Table  # noqa: E402


HEADERS = ("Username", "Email", "Created", "Owns", "Joined")


async def main() -> None:
    try:
        async with AsyncSessionFactory() as session:
            users = (await session.exec(select(User_Table).order_by(User_Table.usr_created_date.asc()))).all()
            rows = [
                (
                    user.usr_name,
                    user.usr_email,
                    user.usr_created_date.strftime("%Y-%m-%d"),
                    str(await count_owned_sites(session, user.usr_id)),
                    str(await count_joined_site_memberships(session, user.usr_id)),
                )
                for user in users
            ]
    finally:
        await engine.dispose()

    if not rows:
        print("No accounts yet - create one with: sudo callmemanage user add")
        return
    widths = [max(len(row[i]) for row in (HEADERS, *rows)) for i in range(len(HEADERS))]
    for row in (HEADERS, *rows):
        print("  ".join(value.ljust(width) for value, width in zip(row, widths)).rstrip())
    print(f"\n{len(rows)} account(s). Owns / Joined = sites owned / sites joined as a member.")


if __name__ == "__main__":
    asyncio.run(main())
