import DismissibleError from "../../DismissibleError";
import { useState } from "react";
import { runDeviceCommand } from "../../../api/api_devices";
import getDeviceInformation from "../../../hooks/getDeviceInformation";
import AddressBookFormModal from "./addressBookFormModal";
import Edit_Result from "../../commandResult/edit_command_result";
import { parseJuniperAddressBook } from "./addressBookParser";

export default function AddressBook({ devId, vendor }) {
  const isJuniper = vendor === "juniper";
  const { data, loading, error, clearError, refetch } = getDeviceInformation(
    devId,
    isJuniper ? "get_address_book_information" : null
  );
  const [formMode, setFormMode] = useState(null); // null | "create" | "edit"
  const [selectedKey, setSelectedKey] = useState(null);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState("");

  function handleSaved() {
    setFormMode(null);
    setSelectedKey(null);
    refetch();
  }

  async function handleConfirmDelete(entry) {
    if (!entry?.deletable) {
      setDeleteError("This entry is an Address Set or unsupported format");
      return;
    }
    setDeleting(true);
    setDeleteError("");
    try {
      await runDeviceCommand(devId, "remove_address_book_entry", { name: entry.name });
      setShowDeleteConfirm(false);
      setSelectedKey(null);
      refetch();
    } catch (err) {
      setDeleteError(err.detail || "Failed to delete Address");
    } finally {
      setDeleting(false);
    }
  }

  if (!isJuniper) {
    return <div className="config-placeholder">Address book is supported on Juniper only</div>;
  }

  if (loading && !data) return <div className="center-loading">Loading Address Book data...</div>;

  const entries = data?.normalized ? parseJuniperAddressBook(data.result) : null;
  const selectedEntry = entries?.find((entry) => entry.key === selectedKey) || null;

  return (
    <div className="command-configuration">
      {error && <DismissibleError message={error} onDismiss={clearError} />}

      {formMode ? (
        <AddressBookFormModal
          devId={devId}
          mode={formMode}
          editTarget={formMode === "edit" ? selectedEntry : null}
          onClose={() => setFormMode(null)}
          onSaved={handleSaved}
        />
      ) : entries === null ? (
        data && (
          <pre>{typeof data.result === "string" ? data.result : JSON.stringify(data.result, null, 2)}</pre>
        )
      ) : (
        <>
          <div className="command-output-title">
            <Edit_Result
              featureName="Address"
              selectedLabel={selectedEntry ? `${selectedEntry.name} (${selectedEntry.value})` : ""}
              canEdit={!!selectedEntry?.editable}
              canDelete={!!selectedEntry?.deletable}
              showDeleteConfirm={showDeleteConfirm}
              deleting={deleting}
              deleteError={deleteError} onDismissDeleteError={() => setDeleteError("")}
              onNew={() => setFormMode("create")}
              onEditClick={() => setFormMode("edit")}
              onOpenDeleteConfirm={() => setShowDeleteConfirm(true)}
              onCancelDelete={() => setShowDeleteConfirm(false)}
              onConfirmDelete={() => handleConfirmDelete(selectedEntry)}
              refreshing={loading}
              onRefresh={refetch}
            />
          </div>

          {selectedEntry && !selectedEntry.editable && (
            <div className="config-placeholder">
              {selectedEntry.kind === "address-set"
                ? "This Address Set is displayed from the device in read-only mode"
                : `${selectedEntry.type} is displayed from the device and can be deleted, but only IP Prefix can be edited currently`}
            </div>
          )}

          {entries.length === 0 ? (
            <div className="config-placeholder">No addresses in Global Address Book</div>
          ) : (
            <div className="security-table-container">
              <table className="security-data-table">
                <thead>
                  <tr>
                    <th>No</th>
                    <th>Name</th>
                    <th>Type</th>
                    <th>Value</th>
                    <th>Description</th>
                  </tr>
                </thead>
                <tbody>
                  {entries.map((entry, index) => (
                    <tr
                      key={entry.key || `${entry.name}-${index}`}
                      className={`row-clickable ${entry.key === selectedKey ? "row-selected" : ""}`}
                      onClick={() => setSelectedKey(entry.key === selectedKey ? null : entry.key)}
                    >
                      <td>{index + 1}</td>
                      <td>{entry.name}</td>
                      <td>{entry.type}</td>
                      <td>{entry.value}</td>
                      <td>{entry.description || "-"}</td>
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
