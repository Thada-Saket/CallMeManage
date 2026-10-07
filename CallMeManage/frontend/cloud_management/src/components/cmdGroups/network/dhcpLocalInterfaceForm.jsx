import DismissibleError from "../../DismissibleError";
import {useEffect, useRef, useState} from "react";
import getDeviceInformation from "../../../hooks/getDeviceInformation";
import {runDeviceCommand, validateDeviceCommand} from "../../../api/api_devices";
import {LOCAL_DHCP_GROUP, readLocalDhcpGroups, localInterfaceOptions, localGroupChanges} from "../../../utils/dhcpLocalServer";

// (2026-09) err.detail ของ DHCP_LOCAL_GROUP_CHANGED/DHCP_LOCAL_MEMBER_NOT_FOUND/
// DHCP_LOCAL_INTERFACE_CONFLICT/DHCP_LOCAL_RELAY_CONFLICT (ดู
// device_router.py's set_dhcp_local_interfaces branch) เป็น {code, message}
// object - ดึง .message ออกมาก่อนเสมอ ไม่งั้น React จะ throw ตอนเรนเดอร์
function errorMessage(err, fallback) {
  const detail = err?.detail;
  if (detail && typeof detail === "object") return detail.message || fallback;
  return detail || err?.message || fallback;
}

function emptyRow() {
  return {name: "", mode: "single", upto: ""};
}

function isSingleMember(member) {
  return member.editable && !member.upto && !member.exclude;
}

function rowsFromMembers(members) {
  const rows = members.filter(isSingleMember).map((member) => ({
    name: member.name,
    mode: "single",
    upto: "",
  }));
  return rows.length ? rows : [emptyRow()];
}

// หนึ่ง panel ต่อหนึ่ง dhcp-local-server group จริง (ไม่ flatten ข้าม group) -
// Apply แยกต่อกลุ่ม แต่ละกลุ่มมี draft/baseline/dirty เป็นของตัวเอง แก้กลุ่มหนึ่ง
// ไม่กระทบอีกกลุ่มเลย
function DhcpLocalGroupPanel({
  devId, groupName, members, allGroups, interfaceOptionsRows, interfaceLoading, relayInterfaces, onRefresh,
}) {
  const [rows, setRows] = useState(() => rowsFromMembers(members));
  const [baseline, setBaseline] = useState(members);
  const [applying, setApplying] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const dirty = useRef(false);
  // ฟอร์มใหม่รับเฉพาะสมาชิกแบบ single เท่านั้น แต่ต้องส่ง Brownfield รูปแบบ
  // range/exclude เดิมกลับไปแบบเดิมทุกครั้ง เพื่อไม่ให้ Apply แถวอื่นลบหรือ
  // เปลี่ยน config ที่ฟอร์มนี้ไม่ได้เปิดให้แก้โดยไม่ตั้งใจ
  const preservedMembers = members.filter((member) => !isSingleMember(member));

  useEffect(() => {
    if (dirty.current) return;
    setBaseline(members);
    setRows(rowsFromMembers(members));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [members]);

  const options = localInterfaceOptions(interfaceOptionsRows, groupName, allGroups, relayInterfaces);

  function changeRows(next) {
    dirty.current = true;
    setRows(next);
    setMessage("");
    setError("");
  }

  function setRowField(index, field, value) {
    changeRows(rows.map((row, rowIndex) => (rowIndex === index ? {...row, [field]: value} : row)));
  }

  async function handleApply(event) {
    event.preventDefault();
    setError("");
    setMessage("");
    try {
      const {changed, ...params} = localGroupChanges(
        groupName, baseline, rows, options, relayInterfaces, preservedMembers,
      );
      if (!changed) return setMessage("No changes");
      setApplying(true);
      await validateDeviceCommand(devId, "set_dhcp_local_interfaces", params);
      await runDeviceCommand(devId, "set_dhcp_local_interfaces", params);
      dirty.current = false;
      setBaseline(params.members);
      await onRefresh();
      setMessage(`Local DHCP interfaces saved for ${groupName}`);
    } catch (err) {
      setError(errorMessage(err, "Failed to configure Local DHCP interface"));
    } finally {
      setApplying(false);
    }
  }

  async function handleRefresh() {
    dirty.current = false;
    setError("");
    setMessage("");
    await onRefresh();
  }

  return (
    <div className="command-configuration" style={{marginBottom: "1.5rem"}}>
      <div className="command-output-title">{groupName}</div>
      <form className="interface-configuration-form" onSubmit={handleApply}>
        {error && <DismissibleError message={error} onDismiss={() => setError("")} />}
        {message && <div role="status">{message}</div>}
        {rows.map((row, index) => (
          <div key={index} className="interface-configuration-form-field-third">
            <label className="data-label" htmlFor={`local-dhcp-${groupName}-interface-${index}`}>
              Interface {index + 1}
            </label>
            <select
              id={`local-dhcp-${groupName}-interface-${index}`}
              value={row.name}
              disabled={applying || interfaceLoading}
              onChange={(event) => setRowField(index, "name", event.target.value)}
            >
              <option value="">-- Select Interface --</option>
              {row.name && !options.includes(row.name) && (
                <option value={row.name}>{row.name} (existing member)</option>
              )}
              {options.filter((option) => !preservedMembers.some((member) => member.name === option)).map((option) => (
                <option
                  key={option}
                  value={option}
                  disabled={rows.some((otherRow, otherIndex) => otherIndex !== index && otherRow.name === option)}
                >
                  {option}
                </option>
              ))}
            </select>

            {index === 0 ? (
              <button type="button" className="mini-btn btn-ghost" disabled={applying}
                onClick={() => changeRows([...rows, emptyRow()])} aria-label={`Add ${groupName} interface`}>+</button>
            ) : (
              <button type="button" className="mini-btn btn-ghost" disabled={applying}
                onClick={() => changeRows(rows.filter((_, rowIndex) => rowIndex !== index))}
                aria-label={`Remove ${groupName} interface ${index + 1}`}>−</button>
            )}
          </div>
        ))}

        {preservedMembers.map((member, index) => (
          <div className="interface-configuration-form-field" key={index}>
            <label className="data-label">Other Config {index + 1}</label>
            <input
              type="text"
              disabled
              readOnly
              value={`${member.name}${member.upto ? ` to ${member.upto}` : ""}${member.exclude ? " (exclude)" : ""}`}
              aria-label={`Preserved DHCP configuration ${index + 1}`}
            />
          </div>
        ))}

        <div className="interface-form-btn-container">
          <button type="submit" className="btn btn-primary" disabled={applying || interfaceLoading}>
            {applying ? "Applying..." : "Apply"}
          </button>
          <button type="button" className="btn btn-ghost" disabled={applying || interfaceLoading} onClick={handleRefresh}>
            Refresh
          </button>
        </div>
      </form>
    </div>
  );
}

export default function DhcpLocalInterfaceForm({devId, result, relayInterfaces, loading, onRefresh}) {
  const {data: interfaceData, loading: interfaceLoading, error: interfaceError, clearError: clearInterfaceError, refetch: refetchInterfaces} =
    getDeviceInformation(devId, "get_interface_list");

  async function handleRefreshAll() {
    await Promise.all([onRefresh(), refetchInterfaces()]);
  }

  const groups = readLocalDhcpGroups(result);
  // Greenfield: CM-DHCP ยังไม่เคยถูกสร้างบนอุปกรณ์เลย - แสดง panel ว่างให้เริ่มสร้าง
  // ได้เสมอ (ไม่สร้างซ้ำถ้ามี CM-DHCP จริงอยู่แล้ว - ใช้ตัวจริงตรงๆ ไม่ต่อท้ายอะไร)
  const displayGroups = groups.some((group) => group.name === LOCAL_DHCP_GROUP)
    ? groups
    : [...groups, {name: LOCAL_DHCP_GROUP, members: [], raw: null}];

  return (
    <div>
      {interfaceError && <DismissibleError message={interfaceError} onDismiss={clearInterfaceError} />}
      {displayGroups.map((group) => (
        <DhcpLocalGroupPanel
          key={group.name}
          devId={devId}
          groupName={group.name}
          members={group.members}
          allGroups={groups}
          interfaceOptionsRows={interfaceData?.normalized ? interfaceData.result : []}
          interfaceLoading={interfaceLoading || loading}
          relayInterfaces={relayInterfaces}
          onRefresh={handleRefreshAll}
        />
      ))}
    </div>
  );
}
