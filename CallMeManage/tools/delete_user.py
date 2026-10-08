""" |======= Delete a website account =======|

    .venv/bin/python tools/delete_user.py <username or email>   (or: sudo callmemanage user delete <name>)

Does what "Delete Account" on the website does, through the same delete_user_full():
the account, every site it owns with their devices and history, and its memberships in
other sites. Shows what will be removed and asks for the username before deleting.

Exit code 3 = devices were deleted. Their call-home connections live in the backend
process, which this script cannot reach, so `callmemanage` offers a backend restart.
"""

import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sqlalchemy import func  # noqa: E402
from sqlmodel import select  # noqa: E402

from backend.core.connect_database import AsyncSessionFactory, engine  # noqa: E402
from backend.crud.web_crud.crud_site import count_joined_site_memberships  # noqa: E402
from backend.crud.web_crud.crud_user import (  # noqa: E402
    delete_user_full,
    get_user_by_email_casefold,
    get_user_by_username,
)
from backend.model.models import Device_Information, Site_Table  # noqa: E402


DEVICES_DELETED = 3


async def main(identifier: str) -> int:
    try:
        async with AsyncSessionFactory() as session:
            user = await get_user_by_email_casefold(session, identifier) if "@" in identifier else None
            user = user or await get_user_by_username(session, identifier)
            if user is None:
                raise SystemExit(f"No account '{identifier}'")

            owned = (await session.exec(
                select(Site_Table.site_name, func.count(Device_Information.dev_id))
                .outerjoin(Device_Information, Device_Information.site_id == Site_Table.site_id)
                .where(Site_Table.site_owner_id == user.usr_id)
                .group_by(Site_Table.site_id, Site_Table.site_name)
                .order_by(Site_Table.site_name)
            )).all()
            joined = await count_joined_site_memberships(session, user.usr_id)
            device_count = sum(count for _, count in owned)

            print(f"Account: {user.usr_name} <{user.usr_email}>")
            if owned:
                print("Sites it owns - deleted with all their devices and history:")
                for site_name, count in owned:
                    print(f"  - {site_name} ({count} device(s))")
            else:
                print("Owns no sites.")
            print(f"Member of {joined} other site(s) - only the membership is removed.")
            print("This cannot be undone.")
            if input(f"Type the username '{user.usr_name}' to delete: ").strip() != user.usr_name:
                raise SystemExit("Not deleted")

            name = user.usr_name
            await delete_user_full(session, user.usr_id)
    finally:
        await engine.dispose()

    print(f"Deleted account '{name}'.")
    return DEVICES_DELETED if device_count else 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: delete_user.py <username or email>")
    sys.exit(asyncio.run(main(sys.argv[1].strip())))
