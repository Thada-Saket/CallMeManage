import asyncio
from contextlib import asynccontextmanager, suppress

import uvicorn
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from backend.api.auth_router import router as auth_router
from backend.api.password_reset_router import router as password_reset_router
from backend.api.device_router import router as device_router
from backend.api.cli_router import router as cli_router
from backend.api.bootstrap_router import router as bootstrap_router
from backend.api.site_router import router as site_router
from backend.api.user_router import router as user_router
from backend.bootstrap_cleanup import run_bootstrap_cleanup_loop
from backend.enrollment_cleanup import run_enrollment_cleanup_loop
from backend.conn_socket import callhome_service
from backend.core.redis_client import init_redis, close_redis
from backend.core.log_redaction import install_access_log_redaction
from backend.core.allowed_hosts import build_allowed_hosts
from backend.core.load_environment import load_environment
from backend.cli_generator import CLOUD_SERVER_IP

# Keep the Google OAuth code/state out of uvicorn's access log (Phase 14 policy).
install_access_log_redaction()

# entrypoint เดียวของ backend: รันทั้ง NETCONF call-home listener (port 4334)
# และ FastAPI web server (port 8000) ใน process เดียวกัน - session อุปกรณ์ที่
# เชื่อมต่ออยู่ (callhome_service.sessions) ต้องอยู่ process เดียวกับ endpoint
# ที่สั่งคำสั่งอุปกรณ์ (device_router) ถึงจะเรียก send_payload() ได้จริง ถ้าแยก
# process กันแบบเดิม (callhome_main.py) endpoint นี้จะหา session ไม่เจอเลย
# รันด้วย `python3 app.py` จาก root ของโปรเจกต์
# หมายเหตุ: reload=True ตอน dev จะ restart process ทุกครั้งที่ไฟล์เปลี่ยน ทำให้
# session อุปกรณ์ที่ต่ออยู่ตัดหมด ต้องรอ device call-home กลับมาใหม่


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Redis ต้องพร้อมก่อน callhome_service.start() เสมอ เพราะ background stats
    # poller (_poll_stats_loop) และทุก endpoint ที่ต้องเช็ค JWT denylist/rate
    # limit จะเรียก get_redis() ทันทีที่มี request/รอบ poll แรกเข้ามา - ปิดย้อน
    # ลำดับตอน shutdown (หยุด call-home ก่อน ปิด redis connection ทีหลัง)
    try:
        await init_redis()
    except Exception as exc:
        print(f"[!] Redis rate limiter error: {exc}")
    await callhome_service.start()
    bootstrap_cleanup_task = asyncio.create_task(
        run_bootstrap_cleanup_loop(), name="bootstrap-token-cleanup"
    )
    enrollment_cleanup_task = asyncio.create_task(
        run_enrollment_cleanup_loop(), name="expired-enrollment-cleanup"
    )
    try:
        yield
    finally:
        bootstrap_cleanup_task.cancel()
        enrollment_cleanup_task.cancel()
        with suppress(asyncio.CancelledError):
            await bootstrap_cleanup_task
        with suppress(asyncio.CancelledError):
            await enrollment_cleanup_task
        await callhome_service.stop()
        await close_redis()


app = FastAPI(title="Multi-Vendor NETCONF Cloud Manager API", version="1.0", lifespan=lifespan)


# จัดรูปแบบ error ตอน validate input ไม่ผ่านให้อ่านง่ายขึ้น (บอกเฉพาะ field และ message โดยไม่สะท้อนค่า input กลับไป)
async def validation_exception_handler(request: Request, exception: RequestValidationError):
    friendly_error = []
    for error_detail in exception.errors():
        where_is_error = " -> ".join(str(part) for part in error_detail["loc"])
        what_gone_wrong = error_detail["msg"]
        friendly_error.append({"field": where_is_error, "message": what_gone_wrong})
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"validation_issues": friendly_error},
    )


app.add_exception_handler(RequestValidationError, validation_exception_handler)

# origin ที่อนุญาตให้เรียก api ได้ (frontend รันผ่าน vite dev server พอร์ท 8080 คนละ
# origin กับ api นี้) - เพิ่ม IP ของเครื่อง dev เท่าที่ใช้จริงตอนนี้ ต้องทบทวนอีกทีก่อน deploy จริง

# |===== HTTP =====|
# origins = [
#     "http://localhost:8080",
#     "http://127.0.0.1:8080",
#     "http://172.16.10.249:8080",
#     "http://192.168.138.129:8080",
#     "http://192.168.159.17:8080",
#     "http://100.90.80.70:8080",
#     "http://www.callmemanage.local:8080"
# ]

# # |===== HTTPS =====|
origins = [
    "https://localhost",
    "https://127.0.0.1",
]

# V4 (pentest 2026-10-05): no "*" — only hosts this deployment really serves.
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=build_allowed_hosts(load_environment(), CLOUD_SERVER_IP),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(password_reset_router)
app.include_router(device_router)
app.include_router(cli_router)
app.include_router(bootstrap_router)
app.include_router(site_router)
app.include_router(user_router)


@app.get("/", tags=["Root"])
async def read_root():
    return {"message": "Multi-Vendor NETCONF Cloud Manager API"}


@app.get("/health")
async def health():
    return {"status": "ok"}


# Entry point of the callmemanage-backend service and of install-packages/start_service.sh. Host, port and
# certificate come from the config file (BIND_HOST, BACKEND_PORT, TLS_CERT_FILE, TLS_KEY_FILE).
# One worker only: device sessions live in this process's memory.
if __name__ == "__main__":
    settings = load_environment()
    uvicorn.run(
        "app:app",
        host=settings.BIND_HOST,
        port=settings.BACKEND_PORT,
        workers=1,
        reload=False,
        # the real client IP (X-Forwarded-For) is trusted only from this machine (the frontend proxy)
        proxy_headers=True,
        forwarded_allow_ips="127.0.0.1",
        ssl_certfile=settings.TLS_CERT_FILE,
        ssl_keyfile=settings.TLS_KEY_FILE,
    )
