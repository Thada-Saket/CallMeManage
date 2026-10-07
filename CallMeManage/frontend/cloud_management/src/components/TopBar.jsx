import { useState } from "react";
import { Link, useNavigate, useLocation } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import SignOutConfirmModal from "./SignOutConfirmModal";

export default function TopBar() {
  const { logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [showSignOutConfirm, setShowSignOutConfirm] = useState(false);
  const [signingOut, setSigningOut] = useState(false);

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
