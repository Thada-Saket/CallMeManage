""" |======= API Generate Bootstrap Config =======| """

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlmodel.ext.asyncio.session import AsyncSession

# เรียกค่าตัวแปรและฟังก์ชั่นจากไฟล์อื่นมาทำงาน
from backend.api.user_deps import get_current_user
from backend.cli_generator import ADMIN_USERNAME, CLOUD_SERVER_IP, CLOUD_SERVER_PORT
from backend.core.connect_database import get_session
from backend.core.rbac import can_manage_site, get_effective_role
from backend.device_enrollment_workflow import EnrollmentWorkflowError, create_pending_enrollment_cli
from backend.model.models import User_Table
from backend.schema.schema import CliGenerateRequest

router = APIRouter(prefix="/cli", tags=["cli"])

# port ของ FastAPI web server
BOOTSTRAP_API_PORT = 8000

# data ที่ส่งเข้า generator: ไม่มี vendor/site_id และเปิดค่า SecretStr ของ Local Administrator (Phase 10) เฉพาะตรงนี้
# (ใน memory ชั่วคราว - ไม่ log, ไม่ persist) ; toggle ปิด = ไม่มี field local_admin_* เลย
def _request_data(body: CliGenerateRequest) -> dict:
    data = body.model_dump(
        exclude={"vendor", "site_id", "pending_device_id", "local_admin_password"},
        exclude_none=True,
    )
    if body.add_local_administrator and body.local_admin_password is not None:
        data["local_admin_password"] = body.local_admin_password.get_secret_value()
    else:
        data.pop("local_admin_username", None)
    return data


# ตรวจสิทธิ์ Site ของผู้ที่กด Generate: ไม่มีสิทธิ์/Site ไม่มีอยู่ตอบ 404 เหมือนกัน (ไม่เปิดเผยว่า Site มีอยู่)
# pending/invited member ไม่มีสิทธิ์เพราะ get_effective_role นับเฉพาะ approved
async def _require_site_manage(session: AsyncSession, site_id: str, usr_id: str) -> None:
    role = await get_effective_role(session, usr_id, site_id)
    if role == "unauthorized":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Site not found.")
    if not can_manage_site(role):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only the Site Owner or Site Admin can add devices")


# Token flow: RBAC ก่อนสร้างข้อมูลใด ๆ -> workflow (ไม่ commit) -> commit ครั้งเดียว | ล้มเหลว = rollback ทั้งหมด
# error ที่ตอบกลับเป็น domain error ที่ sanitized แล้วเท่านั้น (ไม่มี token/hash/SQL parameters)
async def _generate_with_enrollment(body: CliGenerateRequest, current_user: User_Table, session: AsyncSession) -> dict:
    await _require_site_manage(session, body.site_id, current_user.usr_id)
    data = _request_data(body)
    try:
        result = await create_pending_enrollment_cli(
            session,
            site_id=body.site_id,
            vendor=body.vendor,
            data=data,
            user_id=current_user.usr_id,
            pending_device_id=body.pending_device_id,
        )
        await session.commit()  # commit เพียงครั้งเดียวของ token flow
    except EnrollmentWorkflowError as error:
        await session.rollback()
        raise HTTPException(status_code=error.status_code, detail=error.detail) from None
    except Exception:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Could not generate the CLI. Please try again."
        ) from None
    return result.response


# api ดึงข้อมูล username และ ip สำหรับเชื่อมต่อ
# V3: ต้อง login ก่อน - ข้อมูลนี้เผย IP/port ของ call-home server และชื่อ management user
# (ครึ่งหนึ่งของ credential ที่อุปกรณ์ใช้ login) จึงไม่ควรเปิดให้ทุกคนบนอินเทอร์เน็ตดึงได้
# หน้า CLI Generator ที่เรียก endpoint นี้ล็อกอินอยู่แล้ว การใส่ auth จึงไม่กระทบ UX
@router.get("/server-info", dependencies=[Depends(get_current_user)])
async def get_cli_server_info():
    return {"cloud_server_ip": CLOUD_SERVER_IP, "cloud_server_port": CLOUD_SERVER_PORT, "admin_username": ADMIN_USERNAME}

# api ที่ใช้สำหรับการสร้าง cli config ให้อุปกรณ์ callhome มายัง server
@router.post("/generate")
async def generate_cli_command(
    body: CliGenerateRequest,
    current_user: User_Table = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
    response: Response = None,
):
    # ผลลัพธ์อาจมี one-time enrollment token และ Local Administrator password
    # (Cisco/Huawei) จึงห้าม browser หรือ reverse proxy เก็บ response นี้ไว้ใน cache
    if response is not None:
        response.headers["Cache-Control"] = "no-store"
    # Phase 11: public API มีทางเดียวคือ One-Time Token Enrollment (ต้องมี Site + สิทธิ์จัดการ Site)
    # ไม่มี site_id = ปฏิเสธก่อนแตะข้อมูลใด ๆ ; client เลือก legacy Call Home config เองไม่ได้
    # (renderer legacy ใน backend/cli_generator.py เหลือไว้เป็น internal compatibility/rollback fixture เท่านั้น)
    if body.site_id is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Site is required.")
    return await _generate_with_enrollment(body, current_user, session)
