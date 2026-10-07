import DismissibleError from "../../DismissibleError";
import { useState } from "react";
import { runDeviceCommand } from "../../../api/api_devices";
import getDeviceInformation from "../../../hooks/getDeviceInformation";
import AddressPoolFormModal from "./addressPoolFormModal";
import Edit_Result from "../../commandResult/edit_command_result";
import { parseAddressPools } from "./addressPoolParser";

// ตาราง "NAT Pool" - ย้ายมาจากแท็บ "NAT Pool" เดิมในหมวด NAT ทั้งก้อน (ยุบแท็บ
// เดิมทิ้งตามที่ user ขอ) logic/backend command เดิมทุกอย่างไม่เปลี่ยน (ยังใช้
// get_nat_pool_information/create_nat_pool/remove_nat_pool เหมือนเดิม แค่ย้าย
// ที่อยู่หน้าเว็บ) ตารางที่ 2 "Address Pool" (คนละแบบกับ NAT Pool) ยังไม่ทำตอนนี้
// ตามที่ user ระบุ - เอาไว้ก่อน
export default function AddressPool({ devId }) {
  const { data, loading, error, clearError, refetch } = getDeviceInformation(devId, "get_nat_pool_information");
  const [formMode, setFormMode] = useState(null); // null | "create" | "edit"
  const [selectedName, setSelectedName] = useState(null);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState("");

  const vendor = data?.result?.vendor;

  function handleSaved() {
    setFormMode(null);
    setSelectedName(null);
    refetch();
  }

  async function handleConfirmDelete(pool) {
    if (!pool) {
      setDeleteError("Selected NAT pool not found. Please refresh the data.");
      return;
    }
    setDeleting(true);
    setDeleteError("");
    try {
      await runDeviceCommand(devId, "remove_nat_pool", { name: pool.name });
      setShowDeleteConfirm(false);
      setSelectedName(null);
      refetch();
    } catch (err) {
      setDeleteError(err.detail || "Failed to delete NAT pool");
    } finally {
      setDeleting(false);
    }
  }

  if (loading && !data) return <div className="center-loading">Loading NAT pool data...</div>;

  const pools = data?.normalized ? parseAddressPools(data.result) : null;
  const selectedPool = pools?.find((pool) => pool.name === selectedName) || null;

  return (
    <div className="command-configuration">
      <div className="command-output-title">
        <Edit_Result
            featureName="NAT pool"
            selectedLabel={selectedPool?.name || ""}
            extraWarning="If still in use by an active NAT rule, the device will reject the deletion."
            canEdit={!!selectedPool}
            canDelete={!!selectedPool}
            showDeleteConfirm={showDeleteConfirm}
            deleting={deleting}
            deleteError={deleteError} onDismissDeleteError={() => setDeleteError("")}
            onNew={() => setFormMode("create")}
            onEditClick={() => setFormMode("edit")}
            onOpenDeleteConfirm={() => setShowDeleteConfirm(true)}
            onCancelDelete={() => setShowDeleteConfirm(false)}
            onConfirmDelete={() => handleConfirmDelete(selectedPool)}
            refreshing={loading}
            onRefresh={refetch}
          />
      </div>
      {error && <DismissibleError message={error} onDismiss={clearError} />}

      {formMode ? (
        <AddressPoolFormModal
          devId={devId}
          mode={formMode}
          editTarget={formMode === "edit" ? selectedPool : null}
          vendor={vendor}
          onClose={() => setFormMode(null)}
          onSaved={handleSaved}
        />
      ) : pools === null ? (
        data && (
          <pre>{typeof data.result === "string" ? data.result : JSON.stringify(data.result, null, 2)}</pre>
        )
      ) : (
        <>
          

          {pools.length === 0 ? (
            <div className="config-placeholder">No NAT pools</div>
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Pool Name</th>
                  <th>Start Address</th>
                  <th>End Address</th>
                  <th>Netmask</th>
                </tr>
              </thead>
              <tbody>
                {pools.map((pool, index) => (
                  <tr
                    key={`${pool.name}-${index}`}
                    className={`row-clickable ${pool.name === selectedName ? "row-selected" : ""}`}
                    onClick={() => setSelectedName(pool.name === selectedName ? null : pool.name)}
                  >
                    <td>{pool.name || "-"}</td>
                    <td>{pool.ranges?.length
                      ? pool.ranges.map((range, rangeIndex) => <div key={rangeIndex}>{range.start || "-"}</div>)
                      : pool.start || "-"}</td>
                    <td>{pool.ranges?.length
                      ? pool.ranges.map((range, rangeIndex) => <div key={rangeIndex}>{range.end || "-"}</div>)
                      : pool.end || "-"}</td>
                    <td>{pool.netmask || "-"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </>
      )}
    </div>
  );
}
