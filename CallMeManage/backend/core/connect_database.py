""" |======= Postgres Session Initial =======| """

from sqlalchemy.ext.asyncio import create_async_engine
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlalchemy.orm import sessionmaker
from .load_environment import load_environment

# กำหนดข้อมูลสำหรับเชื่อมต่อกับฐานข้อมูล
# engine = create_async_engine(load_environment().DB_URL, echo=True)
engine = create_async_engine(load_environment().DB_URL)

# ประกาศเครื่องมือที่ใช้เชื่อมต่อกับฐานข้อมูล โดยนำข้อมูลที่กำหนดก่อนหน้ามาใช้
AsyncSessionFactory = sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False
)

# ส่งการเชื่อมต่อ postgresql ออกไปทำงาน หาก function ไหนต้องการติดต่อกับฐานข้อมูล
async def get_session():
    # นำเครื่องมือที่ประกาศมาใช้
    async with AsyncSessionFactory() as session:
        try:    
            yield session
        except Exception as error:
            await session.rollback()
            raise error