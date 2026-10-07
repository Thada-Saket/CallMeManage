import DismissibleError from "./DismissibleError";
import { useState } from "react";
import { leaveSiteMember } from "../api/api_sites";

export default function LeaveSiteModal({ site, onClose, onSiteLeave }) {
    const [error, setError] = useState("");
    const [leaving, setLeaving] = useState(false);
    const isPending = site.my_status === "pending";
    const isInvited = site.my_status === "invited";
    
    async function handleLeaveSite() {
        setError("");
        setLeaving(true);
        try {
            await leaveSiteMember(site.site_id);
            onSiteLeave();
            onClose();
        } catch (err) {
            setError(err.detail || (isPending ? "Failed to cancel request" : isInvited ? "Failed to decline invitation" : "Failed to leave site"));
        } finally {
            setLeaving(false);
        }
    }

    return (
        <div className="modal-overlay" onClick={onClose}>
            <div className="modal-card" onClick={(event) => event.stopPropagation()}>
                <div className="modal-header">
                    <h2>
                        {isPending ? "Confirm Cancel Request" : isInvited ? "Confirm Declining Invitation" : "Confirm Leaving Site"}
                    </h2>
                </div>
                <p>
                    {isPending ? "Are you sure you want to cancel your request to join this site?" : isInvited ? "Are you sure you want to decline this invitation?" : "Are you sure you want to leave this site?"}
                </p>

                {error && <DismissibleError message={error} onDismiss={() => setError("")} />}

                <div className="modal-actions">
                    <button
                        type="button"
                        className="btn btn-ghost"
                        onClick={onClose}
                        disabled={leaving}
                    >
                        Cancel
                    </button>
                    <button 
                        type="button" 
                        className="btn btn-danger" 
                        onClick={handleLeaveSite} 
                        disabled={leaving}
                    >
                        {isPending
                            ? (leaving ? "Canceling Request..." : "Cancel Request")
                            : isInvited
                              ? (leaving ? "Declining..." : "Decline Invitation")
                              : leaving ? "Leaving Site..." : "Leave Site"}
                    </button>
                </div>
            </div>
        </div>
    )
}
