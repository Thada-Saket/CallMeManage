import { useState } from "react";

// ถามหลัง login ว่าอยากดูขั้นตอนเพิ่มอุปกรณ์ตัวแรกไหม (หน้า Sites.jsx) - พื้นหลังเบลอชัด
// กว่า modal ปกติ (.modal-overlay-blur) ให้ผู้ใช้โฟกัสคำถามนี้ก่อน · ด้านบนเป็นภาพประกอบ
// + คำทักทาย และสรุปสั้น ๆ ว่า tour จะพาทำอะไรบ้าง 3 อย่าง (ตรงกับ 6 ขั้นจริงใน
// utils/onboardingTour.js แบบย่อ) ให้ผู้ใช้รู้ว่าคุ้มเวลาก่อนตัดสินใจ
// ติ๊ก "Don't ask me again" แล้วกดปุ่มไหนก็ได้ = ไม่ถามอีก
const HIGHLIGHTS = [
  {
    title: "Create a site",
    text: "Group the devices of one location together",
    icon: (
      <>
        <path d="M3 21h18" />
        <path d="M5 21V7l7-4 7 4v14" />
        <path d="M9 21v-6h6v6" />
      </>
    ),
  },
  {
    title: "Add a device",
    text: "Generate the commands for your router or switch",
    icon: (
      <>
        <rect x="3" y="4" width="18" height="12" rx="2" />
        <path d="M7 20h10" />
        <path d="M12 16v4" />
      </>
    ),
  },
  {
    title: "Connect it",
    text: "Paste the commands and watch it come online",
    icon: (
      <>
        <path d="M5 12.55a11 11 0 0 1 14.08 0" />
        <path d="M1.42 9a16 16 0 0 1 21.16 0" />
        <path d="M8.53 16.11a6 6 0 0 1 6.95 0" />
        <circle cx="12" cy="20" r="1" />
      </>
    ),
  },
];

export default function TourPromptModal({ onAccept, onDecline }) {
  const [dontAskAgain, setDontAskAgain] = useState(false);

  return (
    <div className="modal-overlay modal-overlay-blur" onClick={() => onDecline({ dontAskAgain })}>
      <div
        className="modal-card tour-prompt-card"
        role="dialog"
        aria-modal="true"
        aria-labelledby="tour-prompt-title"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="tour-prompt-hero" aria-hidden="true">
          <div className="tour-prompt-hero-icon">
            <svg viewBox="0 0 24 24" width="34" height="34" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M4.5 16.5c-1.5 1.26-2 5-2 5s3.74-.5 5-2c.71-.84.7-2.13-.09-2.91a2.18 2.18 0 0 0-2.91-.09z" />
              <path d="M12 15l-3-3a22 22 0 0 1 2-3.95A12.88 12.88 0 0 1 22 2c0 2.72-.78 7.5-6 11a22.35 22.35 0 0 1-4 2z" />
              <path d="M9 12H4s.55-3.03 2-4c1.62-1.08 5 0 5 0" />
              <path d="M12 15v5s3.03-.55 4-2c1.08-1.62 0-5 0-5" />
            </svg>
          </div>
        </div>

        <h2 id="tour-prompt-title" className="tour-prompt-title">Welcome aboard! 👋</h2>
        <p className="tour-prompt-text">
          New here? Let us walk you through adding your first device. We will point at each button along the way, so
          you can follow along at your own pace.
        </p>

        <ul className="tour-prompt-highlights">
          {HIGHLIGHTS.map((item, index) => (
            <li key={item.title} className="tour-prompt-highlight">
              <span className="tour-prompt-highlight-icon" aria-hidden="true">
                <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  {item.icon}
                </svg>
              </span>
              <span className="tour-prompt-highlight-text">
                <strong>{index + 1}. {item.title}</strong>
                <span>{item.text}</span>
              </span>
            </li>
          ))}
        </ul>

        <p className="tour-prompt-time">
          <span aria-hidden="true">⏱</span> Takes about 2 minutes · you can skip anytime
        </p>

        <div className="tour-prompt-actions">
          <button type="button" className="btn btn-primary tour-prompt-ok" onClick={() => onAccept({ dontAskAgain })}>
            OK, show me around
          </button>
          <button type="button" className="btn btn-ghost" onClick={() => onDecline({ dontAskAgain })}>
            Cancel
          </button>
        </div>

        <label className="tour-prompt-dont-ask">
          <input
            type="checkbox"
            checked={dontAskAgain}
            onChange={(event) => setDontAskAgain(event.target.checked)}
          />
          Don&apos;t ask me again
        </label>
      </div>
    </div>
  );
}
