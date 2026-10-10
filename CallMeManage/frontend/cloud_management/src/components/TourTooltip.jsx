import { useLayoutEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { TOUR_STEPS, endTour } from "../utils/onboardingTour";

// กล่องข้อความของ onboarding tour พร้อมลูกศรชี้ element เป้าหมาย - หาเป้าหมายด้วย
// attribute data-tour="<target>" (ไม่ต้องส่ง ref ข้าม component) แล้ววางกล่องไว้ใต้
// เป้าหมาย ถ้าที่ว่างด้านล่างไม่พอค่อยย้ายไปไว้ด้านบน ลูกศรเลื่อนตามให้ชี้กลางเป้าหมาย
// เสมอแม้กล่องถูกดันเข้าขอบจอ · placement="right" วางกล่องทางขวาของเป้าหมาย ลูกศรชี้
// ไปทางซ้าย (ใช้กับเป้าหมายที่มีเนื้อหาสำคัญอยู่ด้านล่าง เช่นฟอร์ม - วางล่างแล้วบังช่องกรอก)
// ด้านขวาไม่พอ (จอแคบ/มือถือ) ถอยกลับไปวางล่าง/บนตามปกติ
//
// ตำแหน่งคำนวณใหม่ทุกเฟรมระหว่างแสดง (requestAnimationFrame) - เป้าหมายขยับได้หลายทาง
// (เลื่อนหน้า, ย่อจอ, การ์ด CLI โหลดเสร็จแล้วดันปุ่มลง, แถบ sticky) ตามทุกกรณีด้วยวิธีเดียว
// · position:fixed ใน portal ที่ body จึงไม่โดน overflow/transform ของ parent ตัดทิ้ง
const GAP = 12;
const EDGE = 12;
const WIDTH = 300;

export default function TourTooltip({ target, step, title, children, actions, scrollIntoView = true, placement = "auto" }) {
  const boxRef = useRef(null);
  const [pos, setPos] = useState(null);
  const scrolledRef = useRef(false);

  useLayoutEffect(() => {
    let frame = 0;
    let lastKey = "";
    const update = () => {
      const el = document.querySelector(`[data-tour="${target}"]`);
      const box = boxRef.current;
      if (!el || !box || el.getClientRects().length === 0) {
        if (lastKey !== "hidden") {
          lastKey = "hidden";
          setPos(null);
        }
      } else {
        if (scrollIntoView && !scrolledRef.current) {
          scrolledRef.current = true;
          el.scrollIntoView({ block: "center", behavior: "smooth" });
        }
        const rect = el.getBoundingClientRect();
        const width = Math.min(WIDTH, window.innerWidth - EDGE * 2);
        const height = box.offsetHeight;
        let side;
        let top;
        let left;
        let arrowLeft = 0;
        let arrowTop = 0;
        if (placement === "right" && rect.right + GAP + width <= window.innerWidth - EDGE) {
          side = "right";
          const centerY = rect.top + rect.height / 2;
          left = rect.right + GAP;
          top = Math.min(Math.max(centerY - height / 2, EDGE), window.innerHeight - height - EDGE);
          arrowTop = Math.min(Math.max(centerY - top, 18), height - 18);
        } else {
          const below = rect.bottom + GAP + height <= window.innerHeight - EDGE || rect.top - GAP - height < EDGE;
          side = below ? "below" : "above";
          top = below ? rect.bottom + GAP : rect.top - GAP - height;
          const centerX = rect.left + rect.width / 2;
          left = Math.min(Math.max(centerX - width / 2, EDGE), window.innerWidth - width - EDGE);
          arrowLeft = Math.min(Math.max(centerX - left, 18), width - 18);
        }
        const ring = {
          top: Math.round(rect.top) - 4,
          left: Math.round(rect.left) - 4,
          width: Math.round(rect.width) + 8,
          height: Math.round(rect.height) + 8,
        };
        const key = `${Math.round(top)}:${Math.round(left)}:${width}:${side}:${Math.round(arrowLeft)}:${Math.round(arrowTop)}:${ring.top}:${ring.left}:${ring.width}:${ring.height}`;
        if (key !== lastKey) {
          lastKey = key;
          setPos({ top, left, width, side, arrowLeft, arrowTop, ring });
        }
      }
      frame = window.requestAnimationFrame(update);
    };
    update();
    return () => window.cancelAnimationFrame(frame);
  }, [target, scrollIntoView, placement]);

  const stepNumber = TOUR_STEPS.indexOf(step) + 1;

  // กรอบไฮไลต์เป้าหมายวาดแยกเป็น overlay (ไม่ใส่ class ให้ปุ่มเอง - React เขียน className
  // ทับตอน re-render จนไฮไลต์หายได้) · pointer-events:none คลิกปุ่มข้างใต้ได้ตามปกติ
  return createPortal(
    <>
    {pos && (
      <span
        className="tour-target-ring"
        aria-hidden="true"
        style={{ top: pos.ring.top, left: pos.ring.left, width: pos.ring.width, height: pos.ring.height }}
      />
    )}
    <div
      ref={boxRef}
      className={`tour-tooltip is-${pos?.side || "below"}`}
      role="dialog"
      aria-live="polite"
      aria-label={title}
      style={pos
        ? {
          top: pos.top,
          left: pos.left,
          width: pos.width,
          "--tour-arrow-left": `${pos.arrowLeft}px`,
          "--tour-arrow-top": `${pos.arrowTop}px`,
        }
        : { visibility: "hidden", top: 0, left: 0, width: WIDTH }}
    >
      <span className="tour-tooltip-arrow" aria-hidden="true" />
      <div className="tour-tooltip-header">
        {stepNumber > 0 && <span className="tour-tooltip-step">Step {stepNumber} of {TOUR_STEPS.length}</span>}
        <button type="button" className="tour-tooltip-skip" onClick={endTour}>
          Skip tour
        </button>
      </div>
      <strong className="tour-tooltip-title">{title}</strong>
      <div className="tour-tooltip-body">{children}</div>
      {actions && <div className="tour-tooltip-actions">{actions}</div>}
    </div>
    </>,
    document.body
  );
}
