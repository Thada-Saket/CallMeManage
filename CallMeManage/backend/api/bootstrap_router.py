""" |======= API Download Bootstrap Config =======| """

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlmodel.ext.asyncio.session import AsyncSession

# เรียกฟังก์ชั่นจากไฟล์อื่นมาทำงาน
from backend.core.connect_database import get_session
from backend.crud.web_crud.crud_bootstrap_token import consume_bootstrap_token

router = APIRouter(prefix="/bootstrap", tags=["bootstrap"])


# api สำหรับให้อุปกรณ์ดึง config ไปทำงาน โดยจะดึงได้แค่ครั้งเดียวต่อ 1 config
@router.get("/{token}/config.txt")
async def download_bootstrap_config(
    token: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    client_ip = request.client.host if request.client else None
    record = await consume_bootstrap_token(session, token, client_ip)
    if record is None or record.bst_config_payload is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    return Response(
        content=record.bst_config_payload,
        media_type="text/plain",
        headers={
            "Connection": "close",
            "Cache-Control": "no-store, private",
            "Pragma": "no-cache",
            "Expires": "0",
            "X-Content-Type-Options": "nosniff",
        },
    )
