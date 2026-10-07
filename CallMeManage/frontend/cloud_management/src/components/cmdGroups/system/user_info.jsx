import DismissibleError from "../../DismissibleError";
import { useState } from "react";
import getDeviceInformation from "../../../hooks/getDeviceInformation";
import { runDeviceCommand } from "../../../api/api_devices";
import Edit_Result from "../../commandResult/edit_command_result";
import UserInfoForm from "./UserInfoForm";
import { buildUserCommand, parseLocalUsers, privilegeLabel } from "../../../utils/localUsers.js";
import "../../../assets/css/userInfo.css";

function errorMessage(err, fallback) {
  const detail = err?.detail;
  if (detail && typeof detail === "object") return detail.message || fallback;
  return detail || fallback;
}

// System Management > User Management - local user บนอุปกรณ์ (Cisco/Juniper/Huawei) อ่านสดด้วย get_local_user
// backend normalize เป็น {users:[{username, privilege}]} และกรอง Netconf-MGMT ออกแล้ว
// ตาราง/ปุ่มใช้แบบเดียวกับหน้า Juniper NAT (Edit_Result + เลือกแถวก่อน Edit/Delete)
export default function UserInfo({ devId, vendor }) {
  const { data, loading, error, clearError, refetch } = getDeviceInformation(devId, "get_local_user");
  const [formMode, setFormMode] = useState(null); // null | "create" | "edit"
  const [selectedName, setSelectedName] = useState(null);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState("");

  const users = data?.normalized ? parseLocalUsers(data.result) : null;
  const selectedUser = users?.find((user) => user.username === selectedName) || null;

  if (loading && !data) return <div className="center-loading">Loading local users...</div>;

  function handleSaved() {
    setFormMode(null);
    setSelectedName(null);
    refetch();
  }

  async function handleConfirmDelete() {
    if (!selectedUser || deleting) return;
    setDeleting(true);
    setDeleteError("");
    try {
      const { command, parameters } = buildUserCommand({ mode: "delete", vendor, target: selectedUser });
      await runDeviceCommand(devId, command, parameters);
      setShowDeleteConfirm(false);
      setSelectedName(null);
      refetch();
    } catch (err) {
      setDeleteError(errorMessage(err, "Failed to delete local user"));
    } finally {
      setDeleting(false);
    }
  }

  return (
    <div className="command-configuration user-info-page">
      {error && <DismissibleError message={error} onDismiss={clearError} />}

      {formMode ? (
        <UserInfoForm
          devId={devId}
          vendor={vendor}
          mode={formMode}
          target={formMode === "edit" ? selectedUser : null}
          existingUsers={users || []}
          onSaved={handleSaved}
          onClose={() => setFormMode(null)}
        />
      ) : (
        <>
          <div className="command-output-title">
            <Edit_Result
              featureName="Local User"
              selectedLabel={selectedUser?.username || ""}
              canEdit={!!selectedUser}
              editDisabledReason="Select a user first"
              canDelete={!!selectedUser}
              deleteDisabledReason="Select a user first"
              showDeleteConfirm={showDeleteConfirm}
              deleting={deleting}
              deleteError={deleteError}
              onDismissDeleteError={() => setDeleteError("")}
              onNew={() => setFormMode("create")}
              onEditClick={() => selectedUser && setFormMode("edit")}
              onOpenDeleteConfirm={() => {
                setDeleteError("");
                setShowDeleteConfirm(true);
              }}
              onCancelDelete={() => {
                setShowDeleteConfirm(false);
                setDeleteError("");
              }}
              onConfirmDelete={handleConfirmDelete}
              refreshing={loading}
              onRefresh={refetch}
            />
          </div>

          {users === null ? (
            !error && data && <div className="config-placeholder">Unable to read local users from this device</div>
          ) : users.length === 0 ? (
            <div className="config-placeholder">No local users configured</div>
          ) : (
            <div className="table-scroll">
              <table className="data-table user-info-table">
                <thead>
                  <tr>
                    <th>Username</th>
                    <th>Privilege</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map((user) => (
                    <tr
                      key={user.username}
                      className={`row-clickable ${user.username === selectedName ? "row-selected" : ""}`}
                      onClick={() => setSelectedName(user.username === selectedName ? null : user.username)}
                    >
                      <td>{user.username}</td>
                      <td>{privilegeLabel(user.privilege)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </div>
  );
}
