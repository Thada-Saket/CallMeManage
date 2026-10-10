import DismissibleError from "../components/DismissibleError";
// |====== Device Page Render on Browser ======|

// useEffect = สิ่งที่จะให้ทำงานต่อหลังจาก render หน้าเว็บเสร็จ
// useReducer = เก็บ state ที่ซับซ้อน (ชุดข้อมูลที่เคยโหลดมาแล้ว + อยู่ชุดไหน) แบบอ่านค่าล่าสุดได้เสมอ
// useRef = สร้างตัวแปรค่าคงที่ที่จะอยู่ตลอดการทำงาน แต่ถ้ามีการเปลี่ยนแปลงจะไม่ render หน้าใหม่
// useState = สร้างตัวแปรเก็บค่าเก็บสถานะที่สามารถเปลี่ยนได้ตลอด ถ้ามีการเปลี่ยนแปลงจะ render หน้าใหม่
// useNaviate = redirect
// useSearchParams = ใช้อ่านและแก้ไข Query String
import { useEffect, useReducer, useRef, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";

// import global components
import TopBar from "../components/TopBar";

// import device components
import DeviceCard from "../components/DeviceCard";
import { Pagination } from "../components/Pagination";

// import api function
import { listDevices } from "../api/api_devices";
import { createGenerationGuard, createPoller, POLL_BASE_MS, POLL_MAX_MS } from "../utils/devicePoller";
import { cliGeneratorUrl } from "../utils/deviceEnrollmentRoutes";
import TourTooltip from "../components/TourTooltip";
import { advanceTour, useTourStep } from "../utils/onboardingTour";

// สถานะอุปกรณ์อัปเดตเองแบบ real-time (อ้างอิงจาก basic_info.jsx) - ยิง GET /devices/ query DB ไม่ใช้ Netconf RPC
// รอบปกติ 10 วิ, ล้มเหลวถอยเป็น 20/40/60 วิ (ดู utils/devicePoller.js) - pending card ที่ backend เปลี่ยนเป็น active
// ในอนาคต (Phase 8) จะอัปเดต card เดิมด้วย dev_id เดิมจากรอบ poll นี้ ไม่มี logic activate ฝั่ง frontend
const POLL_INTERVAL_MS = POLL_BASE_MS;

// เก็บ "ชุดข้อมูลที่เคยโหลดมาแล้ว" (stack) + "อยู่ชุดไหนตอนนี้" (index)
// ใช้ reducer แทน useState เพราะ dispatch จะทำงานกับ state ล่าสุดเสมอ ต่างจาก closure ของ setInterval ที่ค่าเก่าค้าง
function navReducer(state, action) {
  switch (action.type) {
    case "reset":
      return { stack: [], index: 0 };
    case "set_page": {
      // วางชุดข้อมูลที่ index ที่กำหนด แล้วตัดชุดถัดไปที่เคย cache ไว้ทิ้ง (อาจไม่ตรง cursor ใหม่แล้ว)
      const stack = state.stack.slice(0, action.index);
      stack[action.index] = action.page;
      return { stack, index: action.index };
    }
    case "go_to_index":
      // เคยโหลดชุดนี้ไว้แล้วใน stack (กด "ก่อนหน้า" ถอยมาก่อน) แค่ขยับตำแหน่ง ไม่ต้อง fetch ใหม่
      return { ...state, index: action.index };
    default:
      return state;
  }
}

// แสดงผลหน้าเว็บรายการอุปกรณ์
export default function Devices() {
  // ฟังก์ชั่นสำหรับ redirect ไปยัง path ที่กำหนด
  const navigate = useNavigate();

  // ตัวแปรเก็บค่า site_id โดยใช้ useSearchParams ไปดึงมาจาก url
  const [searchParams] = useSearchParams();
  const siteId = searchParams.get("site_id");

  const [nav, dispatch] = useReducer(navReducer, { stack: [], index: 0 });
  const [error, setError] = useState("");             // ตัวแปรเก็บค่า error
  const [navBusy, setNavBusy] = useState(false);      // true ระหว่างรอ fetch ชุดถัดไปที่ยังไม่ได้ prefetch ไว้ (เคสกดเร็วมาก)
  // generation ของ Site ปัจจุบัน: เพิ่มทุกครั้งที่ site_id เปลี่ยน/หน้าถูกปิด - response ของ generation เก่าที่กลับมาช้า
  // ถูกทิ้ง ไม่เขียนทับรายการของ Site ใหม่ (ค่า boolean แบบเดิมถูกตั้งกลับเป็น false ทันทีที่ effect ใหม่เริ่ม
  // จึงกัน response ของ Site เก่าไม่ได้)
  const guardRef = useRef(createGenerationGuard());
  const navRef = useRef(nav);                         // เก็บค่า nav ล่าสุดไว้ให้ setInterval อ่านได้ (ไม่ให้ค่าค้างจาก closure)
  const prefetchRef = useRef(null);                   // ชุดถัดไปที่แอบโหลดล่วงหน้าไว้เงียบ ๆ { afterDevId, promise }

  useEffect(() => {
    navRef.current = nav;
  }, [nav]);

  const currentPage = nav.stack[nav.index] || null;   // ชุดข้อมูลที่กำลังแสดงอยู่ตอนนี้ { items, hasNext }
  const devices = currentPage ? currentPage.items : null;
  const siteRole = currentPage?.siteRole || null;
  const canManageSite = siteRole === "owner" || siteRole === "admin";
  const tourStep = useTourStep();

  // ขอข้อมูลอุปกรณ์ 1 ชุดจาก backend ด้วย cursor ที่กำหนด (afterDevId=null คือชุดแรกสุด)
  async function fetchPage(afterDevId) {
    const result = await listDevices(siteId, afterDevId);
    return { items: result.items, hasNext: result.has_next, siteRole: result.site_role };
  }

  const isCurrent = (generation) => guardRef.current.isCurrent(generation);

  // แอบโหลดชุดถัดไปเงียบ ๆ ไว้ล่วงหน้า ให้กด "ถัดไป" แล้วไม่ต้องรอ
  function prefetchNext(page) {
    if (!page || !page.hasNext || page.items.length === 0) return;
    const afterDevId = page.items[page.items.length - 1].dev_id;
    if (prefetchRef.current && prefetchRef.current.afterDevId === afterDevId) return; // เคย prefetch อันนี้ไปแล้ว
    prefetchRef.current = {
      afterDevId,
      promise: fetchPage(afterDevId).catch(() => null),
    };
  }

  // โหลดชุดแรกสุดใหม่ทั้งหมด (ใช้ตอนเปิดหน้า/สลับ site และตอนกลับมาจาก CLI Generator - ดึงจาก backend สดเสมอ)
  async function loadFirstPage(showError, generation) {
    try {
      const page = await fetchPage(null);
      if (!isCurrent(generation)) return;
      dispatch({ type: "set_page", index: 0, page });
      prefetchRef.current = null;
      prefetchNext(page);
      if (showError) setError("");
    } catch (err) {
      if (isCurrent(generation) && showError) {
        setError(err.detail || "Failed to load devices");
      }
    }
  }

  // รีเฟรชชุดที่กำลังแสดงอยู่ตอนนี้ด้วย cursor เดิม (ใช้ตอน poll ไม่โชว์ error ทับรายการเดิมที่ยังแสดงอยู่)
  // คืน false เมื่อ request ล้มเหลว (poller ใช้ตัดสิน backoff) ; response ที่ stale ไม่นับเป็นความล้มเหลว
  async function refreshCurrentPage(generation = guardRef.current.value) {
    const { stack, index } = navRef.current;
    if (stack.length === 0) return true;
    const prevPage = index > 0 ? stack[index - 1] : null;
    const afterDevId = prevPage ? prevPage.items[prevPage.items.length - 1].dev_id : null;
    try {
      const page = await fetchPage(afterDevId);
      if (!isCurrent(generation)) return true;
      dispatch({ type: "set_page", index, page });
      prefetchRef.current = null;
      prefetchNext(page);
      return true;
    } catch {
      return false;
    }
  }

  // เมื่อค่า Site_Id เปลี่ยนแปลงให้ล้างรายการอุปกรณ์ โหลดใหม่ และเริ่ม poll ใหม่ (recursive timeout ไม่ซ้อนกัน)
  // cleanup: หยุด timer และทำให้ response ที่ค้างอยู่ของ Site เก่า/หน้าที่ปิดไปแล้วถูกทิ้ง
  useEffect(() => {
    const guard = guardRef.current;
    const generation = guard.advance();
    prefetchRef.current = null;
    dispatch({ type: "reset" }); // สลับสาขา (site_id เปลี่ยน) -> โชว์ loading ใหม่แทนรายการเก่าค้าง กลับไปชุดแรก
    loadFirstPage(true, generation);
    const poller = createPoller({
      run: () => refreshCurrentPage(generation),
      baseMs: POLL_INTERVAL_MS,
      maxMs: POLL_MAX_MS,
    });
    poller.start();
    return () => {
      poller.stop();
      guard.advance();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [siteId]);

  // ไปหน้าถัดไป: ถ้าเคยโหลด/prefetch ไว้แล้วใช้เลยไม่ต้องรอ ถ้ายังไม่มีค่อย fetch สด ๆ
  async function goNext() {
    const nextIndex = nav.index + 1;
    if (nextIndex < nav.stack.length) {
      dispatch({ type: "go_to_index", index: nextIndex });
      return;
    }
    if (!currentPage || !currentPage.hasNext || currentPage.items.length === 0) return;
    const afterDevId = currentPage.items[currentPage.items.length - 1].dev_id;
    const generation = guardRef.current.value;

    let page = null;
    if (prefetchRef.current && prefetchRef.current.afterDevId === afterDevId) {
      page = await prefetchRef.current.promise;
    }
    if (!page) {
      setNavBusy(true);
      try {
        page = await fetchPage(afterDevId);
      } catch (err) {
        if (isCurrent(generation)) setError(err.detail || "Failed to load devices");
        setNavBusy(false);
        return;
      }
      setNavBusy(false);
    }
    if (!isCurrent(generation)) return;
    dispatch({ type: "set_page", index: nextIndex, page });
    prefetchRef.current = null;
    prefetchNext(page); // เตรียมชุดถัดไปต่ออีกทอดทันที
  }

  // ย้อนกลับหน้าก่อนหน้า: อยู่ใน stack (cache) อยู่แล้วเสมอ ไม่ต้อง fetch เลย
  function goPrev() {
    if (nav.index === 0) return;
    dispatch({ type: "go_to_index", index: nav.index - 1 });
  }

  // การแสดงผลหน้าเว็บ
  return (
    <div className="app-shell">
      <TopBar />
      <main className="main-content">
        <div className="page-header">
          <div>
            <h1>Devices on this Site</h1>
          </div>
          {canManageSite && <div className="page-header-actions">
            {/* ปุ่มเดียวสำหรับเพิ่มอุปกรณ์: ไปหน้า CLI Generator พร้อม Site ปัจจุบัน (ไม่ต้องกรอก MAC/Serial) */}
            <button
              type="button"
              className="btn btn-primary"
              data-tour="add-device"
              onClick={() => {
                const url = cliGeneratorUrl(siteId);
                // tour ขั้น 2 -> 3: หน้า CLI Generator ชี้ฟอร์มกรอกข้อมูลอุปกรณ์ต่อ
                advanceTour("add-device", "fill-form");
                if (url) navigate(url);
              }}
            >
              + New Device
            </button>
          </div>}
        </div>

        {error && <DismissibleError message={error} onDismiss={() => setError("")} />}
        {devices === null && !error && <div className="center-loading">Loading...</div>}

        <section className="site-section">
          {devices && devices.length > 0 && (
            <Pagination
              hasPrev={nav.index > 0}
              hasNext={!navBusy && !!currentPage?.hasNext}
              onPrev={goPrev}
              onNext={goNext}
            />
          )}
          {devices && devices.length === 0 && (
            <div className="empty-state">
              <h3>No devices yet</h3>
              <p>{canManageSite ? 'Click "+ New Device" to generate a CLI and add your first device.' : "No devices are currently available in this site."}</p>
            </div>
          )}
          {devices && devices.length > 0 && (
            <div className="device-grid">
              {devices.map((device) => (
                <DeviceCard
                  key={device.dev_id}
                  device={device}
                  siteRole={siteRole}
                  onDeleted={() => refreshCurrentPage()}
                  onChanged={() => refreshCurrentPage()}
                />
              ))}
            </div>
          )}
        </section>
      </main>
      {/* tour ขั้น 2 - เฉพาะคนที่เห็นปุ่ม (owner/admin) · ปุ่มซ่อนอยู่ TourTooltip ก็ไม่แสดง */}
      {tourStep === "add-device" && canManageSite && (
        <TourTooltip target="add-device" step="add-device" title="Add your first device">
          You are now inside your new site. Click <strong>+ New Device</strong> to create the commands that connect a
          device to this system.
        </TourTooltip>
      )}
    </div>
  );
}
