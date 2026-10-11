import { useState } from "react";
import { Link, useNavigate, useLocation } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import SignOutConfirmModal from "./SignOutConfirmModal";
import TourPromptModal from "./TourPromptModal";
import { markTourPrompted, setTourStep } from "../utils/onboardingTour";

export default function TopBar() {
  const { logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [showSignOutConfirm, setShowSignOutConfirm] = useState(false);
  const [signingOut, setSigningOut] = useState(false);
  // ปุ่ม Tutorial: เปิด popup เดียวกับที่ถามหลัง login (Sites.jsx) ได้ทุกเมื่อ แม้เคยติ๊ก
  // "Don't ask me again" ไว้ (ผู้ใช้กดเองตั้งใจ) - OK = เริ่ม tour ใหม่ตั้งแต่ขั้น 1 แล้วพาไป
  // หน้า Sites เพราะขั้น 1 ชี้ปุ่ม Create New Site ที่อยู่หน้านั้น
  const [showTourPrompt, setShowTourPrompt] = useState(false);

  function handleTourAccept({ dontAskAgain }) {
    markTourPrompted({ dontAskAgain });
    setShowTourPrompt(false);
    setTourStep("create-site");
    if (location.pathname !== "/sites") navigate("/sites");
  }

  function handleTourDecline({ dontAskAgain }) {
    markTourPrompted({ dontAskAgain });
    setShowTourPrompt(false);
  }

  const isAccountPage = location.pathname === "/account";

  function handleOpenConfirm() {
    setShowSignOutConfirm(true);
  }

  function handleCancelConfirm() {
    if (signingOut) return;
    setShowSignOutConfirm(false);
  }

  async function handleConfirmLogout() {
    if (signingOut) return;
    setSigningOut(true);
    try {
      await logout();
      setShowSignOutConfirm(false);
      navigate("/login", { replace: true });
    } catch {
      setShowSignOutConfirm(false);
      navigate("/login", { replace: true });
    } finally {
      setSigningOut(false);
    }
  }

  return (
    <header className="topbar cant-copy">
      <Link to="/" style={{textDecoration:'none'}}>
        <div className="brand">
          <span className="brand-mark">CMM</span>
          <h3>CallMe Manage</h3>
        </div>
      </Link>
      <div className="topbar-user">
        <button type="button" className="topbar-element" onClick={() => navigate("/sites")}>
          Site Management
        </button>
        <button type="button" className="topbar-element" onClick={() => setShowTourPrompt(true)}>
          Tutorial
        </button>
        {isAccountPage ? (
          <></>
        ) : (
          <button type="button" className="topbar-element" onClick={() => navigate("/account")}>
            My Account
          </button>
        )}
        <button type="button" className="topbar-element" onClick={handleOpenConfirm}>
          Sign Out
        </button>
      </div>

      {showTourPrompt && <TourPromptModal onAccept={handleTourAccept} onDecline={handleTourDecline} />}

      {showSignOutConfirm && (
        <SignOutConfirmModal
          signingOut={signingOut}
          onCancel={handleCancelConfirm}
          onConfirm={handleConfirmLogout}
        />
      )}
    </header>
  );
}
