import { useState } from "react";

// ถามหลัง login ว่าอยากดูขั้นตอนเพิ่มอุปกรณ์ตัวแรกไหม (หน้า Sites.jsx) - รูปแบบ modal
// เดียวกับ InvitationsModal แต่พื้นหลังเบลอชัดกว่า (.modal-overlay-blur) ให้ผู้ใช้โฟกัส
// คำถามนี้ก่อน · ติ๊ก "Don't ask me again" แล้วกดปุ่มไหนก็ได้ = ไม่ถามอีก
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
        <div className="modal-header">
          <h2 id="tour-prompt-title">Show me how?</h2>
        </div>
        <p className="tour-prompt-text">
          Would you like a quick step-by-step guide? It shows you how to create a site, add your first device, and
          connect it to this system.
        </p>
        <label className="tour-prompt-dont-ask">
          <input
            type="checkbox"
            checked={dontAskAgain}
            onChange={(event) => setDontAskAgain(event.target.checked)}
          />
          Don&apos;t ask me again
        </label>
        <div className="modal-actions">
          <button type="button" className="btn btn-ghost" onClick={() => onDecline({ dontAskAgain })}>
            Cancel
          </button>
          <button type="button" className="btn btn-primary" onClick={() => onAccept({ dontAskAgain })}>
            OK
          </button>
        </div>
      </div>
    </div>
  );
}
