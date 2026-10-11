import { useLayoutEffect, useRef } from "react";

// ปุ่ม "ขอ config ใหม่" (refresh) - user ขอให้เป็นปุ่มวงกลมสีเหลืองโดดจากพื้นหลัง และตอน
// กำลังโหลดให้ "เบลอข้อมูล" พร้อมจุด ๆ หมุน เพื่อให้รู้ว่ากำลังโหลดใหม่อยู่
//
// การเบลอข้อมูล: data ของแต่ละหน้าอยู่เป็น sibling ของแถบปุ่มนี้ (ใต้ .command-configuration
// เดียวกัน) child ใช้ CSS ไปเบลอ sibling ของ parent ไม่ได้ จึง toggle class is-refreshing
// ที่ .command-configuration ที่ใกล้ที่สุดผ่าน ref โดยตรง (ทำที่เดียวตรงนี้ ใช้ได้ทุกหน้า
// ที่ผ่าน Edit_Result/Reload_Result โดยไม่ต้องแก้ทีละหน้า) CSS ที่เหลืออยู่ใน App.css
export function Reload_Result({ loading = false, onRefresh = () => {} }) {
  const ref = useRef(null);

  useLayoutEffect(() => {
    const container = ref.current?.closest(".command-configuration");
    if (!container) return undefined;
    container.classList.toggle("is-refreshing", Boolean(loading));
    return () => container.classList.remove("is-refreshing");
  }, [loading]);

  return (
    <>
      <div></div>
      <button
        ref={ref}
        type="button"
        className={`btn-refresh btn-refresh-circle${loading ? " is-loading" : ""}`}
        disabled={loading}
        onClick={onRefresh}
        aria-label={loading ? "Refreshing configuration" : "Refresh / fetch latest configuration"}
        aria-busy={loading ? "true" : undefined}
        title="Refresh / fetch latest configuration"
      >
        {loading ? (
          <span className="btn-refresh-dots" aria-hidden="true">
            <span></span><span></span><span></span>
          </span>
        ) : (
          <span className="btn-refresh-icon" aria-hidden="true">&#x27F3;</span>
        )}
      </button>
    </>
  );
}
