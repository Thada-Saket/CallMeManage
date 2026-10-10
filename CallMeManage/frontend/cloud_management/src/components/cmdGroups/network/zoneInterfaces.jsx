import DismissibleError from "../../DismissibleError";
import { useState } from "react";
import { runDeviceCommand } from "../../../api/api_devices";
import getDeviceInformation from "../../../hooks/getDeviceInformation";
import ZoneInterfacesFormModal from "./zoneInterfacesFormModal";
import Edit_Result from "../../commandResult/edit_command_result";
import { protectedWanInterfaces } from "../../../utils/zoneProtection";
import { rowClickSelection, rowDoubleClick } from "../../../utils/rowDoubleClick";

function ensureArray(value) {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

// Junos: security/zones/security-zone (name, interfaces (list), host-inbound-
// traffic/system-services + protocols) - path ตรงกับที่ set_security_zone/
// apply_zone_member เขียน ยืนยันจริงผ่าน CLI ก่อนเขียนโค้ดนี้ (2026-07-28)
// รอบแรกอ่านแค่ host-inbound-traffic ระดับ zone (sibling ของ "interfaces")
// เพราะคิดว่า per-interface host-inbound-traffic เป็น scope ที่ตั้งใจไม่โชว์ -
// แต่ user เจอจริงว่า zone "WAN" (ตั้งมาด้วยมือก่อนหน้านี้ ไม่ผ่านแอป) ใช้ระดับ
// per-interface ล้วนๆ ไม่มีอะไรอยู่ระดับ zone เลย ทำให้ตาราง/ฟอร์ม edit โชว์ค่าง
// เปล่าทั้งที่อุปกรณ์อนุญาต service ไว้จริง - แก้แล้วโดย union ทั้ง 2 ระดับเข้า
// ด้วยกัน (ดู comment ที่ interfaceServices/interfaceProtocols ด้านล่าง)
// export ไว้ให้ฟอร์มอื่นที่ต้อง default-select "WAN interface" ใช้ร่วมกัน (NAT
// Static/Port Forward's From Zone+WAN Interface, Security Profile's WAN
// Interface, Security Tunnel's ขา Outbound - ดู comment ที่ไฟล์เหล่านั้น) แทน
// ต้องเขียน parse ซ้ำเอง - ตัวนี้คืน zone.interfaces เป็นชื่อเต็มพร้อม unit
// (เช่น "ge-0/0/0.0") ตรงกับ format ที่ get_ip_interface_brief/get_interface_list
// คืนมาอยู่แล้ว เทียบ string ตรงๆ ได้เลยไม่ต้องแปลง
export function parseJuniperZones(result) {
  try {
    const zones = ensureArray(result?.payload?.data?.configuration?.security?.zones?.["security-zone"]);
    return zones.map((zone) => {
      const zoneServices = ensureArray(zone?.["host-inbound-traffic"]?.["system-services"])
        .map((s) => s?.name)
        .filter(Boolean);
      const zoneAllowsNetconf = zoneServices.includes("netconf") || zoneServices.includes("all");
      const interfaceEntries = ensureArray(zone?.interfaces);
      // เจอจริงบน zone "WAN" ของแล็บนี้: host-inbound-traffic ถูกตั้งไว้ระดับ
      // per-interface (security-zone/interfaces/<name>/host-inbound-traffic)
      // ทั้งหมด ไม่มีอะไรอยู่ระดับ zone เลย (ตั้งมาด้วยมือก่อนหน้านี้ ไม่ผ่านแอป)
      // - ถ้าอ่านแค่ระดับ zone แบบเดิม (zoneServices/zoneProtocols) จะได้ [] เสมอ
      // ทั้งที่ Junos ยังอนุญาต service พวกนี้จริงบน interface นั้น (2 ระดับนี้
      // เป็น additive กัน ไม่ใช่ override - ยืนยันจาก Junos docs) เลย union เข้า
      // มาด้วยเพื่อให้ตาราง/ฟอร์ม edit โชว์ค่าที่อนุญาตจริงครบทุก level ไม่ใช่
      // แค่ level เดียวที่แอปเองเป็นคนเขียน
      const interfaceServices = interfaceEntries.flatMap((entry) =>
        ensureArray(entry?.["host-inbound-traffic"]?.["system-services"]).map((s) => s?.name)
      );
      const interfaceProtocols = interfaceEntries.flatMap((entry) =>
        ensureArray(entry?.["host-inbound-traffic"]?.protocols).map((p) => p?.name)
      );
      const zoneProtocols = ensureArray(zone?.["host-inbound-traffic"]?.protocols).map((p) => p?.name).filter(Boolean);
      return {
        name: zone?.name || "",
        interfaces: interfaceEntries.map((i) => i?.name).filter(Boolean),
        services: [...new Set([...zoneServices, ...interfaceServices])].filter(Boolean),
        protocols: [...new Set([...zoneProtocols, ...interfaceProtocols])].filter(Boolean),
        // interface ที่เปิด "netconf" (หรือ "all") ไว้ให้ ไม่ว่าจะเปิดที่ระดับ
        // zone (sibling ของ "interfaces" - แบบที่ set_security_zone เขียน) หรือ
        // per-interface (legacy, เจอจริงบนแล็บนี้ที่ zone "WAN") - ใช้เป็น
        // สัญญาณ "ห้ามลบออกจาก zone" แทนการเดา/เทียบ IP อุปกรณ์ (ลองมาแล้วว่า
        // ใช้ dev_ip ไม่ได้ - แล็บนี้อยู่หลัง NAT ของ GNS3 host ค่า dev_ip ที่
        // backend เห็นเป็น source IP ที่ถูก NAT แล้ว (100.110.120.130) ไม่ตรงกับ
        // IP จริงของ interface บนอุปกรณ์เลยสักตัว - สัญญาณจาก netconf service
        // ตรงๆ นี้เชื่อถือได้กว่าเพราะเป็น mechanism จริงที่ Junos ใช้เปิด/ปิด
        // NETCONF access ไม่ต้องพึ่ง topology ภายนอกเลย)
        netconfInterfaces: interfaceEntries
          .filter((entry) => {
            if (zoneAllowsNetconf) return true;
            const perIfaceServices = ensureArray(entry?.["host-inbound-traffic"]?.["system-services"]).map(
              (s) => s?.name
            );
            return perIfaceServices.includes("netconf") || perIfaceServices.includes("all");
          })
          .map((entry) => entry?.name)
          .filter(Boolean),
      };
    });
  } catch {
    return null;
  }
}

// Cisco: native/zone/security (key "id") - path ตรงกับที่ set_security_zone
// เขียน ไม่มี services/protocols concept แบบ Junos (ควบคุมผ่าน class-map/ACL
// แทน) เลยได้ [] เสมอทั้งคู่
export function parseCiscoZoneList(result) {
  try {
    const zones = ensureArray(result?.payload?.data?.native?.zone?.security);
    return zones.map((zone) => ({ name: zone?.id || "", interfaces: [], services: [], protocols: [] }));
  } catch {
    return null;
  }
}

// เจอบั๊กจริงตอนสร้าง getWanZoneInterfaces (2026-08-03): ฟังก์ชันนี้เดิมเขียน
// สมมติว่า get_switchport_information คืน raw XML shape ตรงๆ
// (`payload.data.native.interface` grouped by type) แต่จริงๆ แล้ว
// normalize_switchport_layer (response_normalizer.py) แปลงให้เป็น **array ของ
// row ที่ flatten แล้ว** ไปตั้งแต่ backend (`[{name: "GigabitEthernet1", layer,
// mode, helpers, raw}, ...]` - name รวม type+id ให้แล้ว, raw คือ leaf ดิบของ
// interface นั้นตัวเดียว) - โค้ดเดิมเลย `switchportResult?.payload` เป็น
// undefined เสมอ (เพราะ argument ที่ส่งเข้ามาจริงคือ array ไม่ใช่ object ที่มี
// .payload) แล้ว early-return {} เงียบๆ ทุกครั้ง ไม่เคยจับ zone-member ได้เลย
// สักตัว (ยืนยันจริงกับ BR2-Router - zone LAN/WAN มีอยู่แต่ตาราง Interface ว่าง
// เปล่าตลอดแม้จะดูเหมือนใช้งานได้ปกติ เพราะ "-" กับ "ว่างเปล่าเพราะบั๊ก" หน้าตา
// เหมือนกันจนไม่มีใครสังเกต) - แก้ให้ iterate row ที่ flatten แล้วตรงๆ แทน
// (zone-member อยู่ที่ row.raw["zone-member"].security)
export function parseCiscoZoneMembership(switchportRows) {
  const membership = {};
  try {
    for (const row of ensureArray(switchportRows)) {
      if (!row?.name) continue;
      const zoneId = row?.raw?.["zone-member"]?.security;
      if (zoneId) (membership[zoneId] ||= []).push(row.name);
    }
  } catch {
    /* best-effort - ตารางยังโชว์ zone ได้ปกติแค่คอลัมน์ Interface ว่าง */
  }
  return membership;
}

export default function ZoneInterfaces({ devId, vendor }) {
  const isJuniper = vendor === "juniper";
  const { data, loading, error, clearError, refetch } = getDeviceInformation(devId, "get_security_zone_information");
  const {
    data: switchportData,
    loading: switchportLoading,
    error: switchportError,
    clearError: clearSwitchportError,
    refetch: refetchSwitchport,
  } = getDeviceInformation(devId, isJuniper ? null : "get_switchport_information");

  const [formMode, setFormMode] = useState(null); // null | "create" | "edit"
  const [selectedName, setSelectedName] = useState(null);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState("");

  const parsedZones = data?.normalized
    ? isJuniper
      ? parseJuniperZones(data.result)
      : parseCiscoZoneList(data.result)
    : null;

  // สมาชิกของ Cisco มาจากคนละคำสั่งกับตัว zone (get_switchport_information) -
  // normalized=true ไม่ได้แปลว่า result เป็น array เสมอ อาจเป็น {ok:false, errors}
  // ซึ่ง parseCiscoZoneMembership จะคืน {} เงียบๆ แล้วตารางโชว์ "-" เหมือน "ไม่มี
  // สมาชิก" ทั้งที่จริงคืออ่านไม่สำเร็จ - อันตรายกว่าตรงที่ฟอร์ม Edit จะเริ่มจาก
  // รายการติ๊กว่างเปล่าแล้วถอดสมาชิกจริงทิ้งทั้งหมดตอน Save จึงแยก "ไม่รู้" ออกจาก
  // "ไม่มี" ให้ชัดแล้วส่งสถานะนี้เข้าฟอร์มด้วย (membersKnown)
  const membershipReady = isJuniper || Boolean(switchportData?.normalized && Array.isArray(switchportData.result));
  const membershipError = isJuniper ? "" : switchportError || (switchportData && !membershipReady
    ? (switchportData.result?.errors || []).map((item) => item.message).filter(Boolean).join("; ")
      || "Failed to read Zone interface members"
    : "");
  const membership = !isJuniper && membershipReady ? parseCiscoZoneMembership(switchportData.result) : {};
  const zones = parsedZones
    ? isJuniper
      ? parsedZones
      : parsedZones.map((zone) => ({
          ...zone,
          interfaces: membership[zone.name] || [],
          membersKnown: membershipReady,
        }))
    : null;

  // Only Juniper WAN-zone members are protected from membership removal.
  const wanProtectedInterfaces = isJuniper ? protectedWanInterfaces(zones) : new Set();

  const selectedZone = zones?.find((zone) => zone.name === selectedName) || null;

  function handleSaved() {
    setFormMode(null);
    setSelectedName(null);
    refetch();
    if (!isJuniper) refetchSwitchport();
  }

  function handleRefresh() {
    refetch();
    if (!isJuniper) refetchSwitchport();
  }

  async function handleConfirmDelete() {
    if (!selectedZone || deleting) return;
    setDeleting(true);
    setDeleteError("");
    try {
      await runDeviceCommand(devId, "remove_security_zone", isJuniper
        ? { zone_name: selectedZone.name }
        : { zone_id: selectedZone.name });
      setShowDeleteConfirm(false);
      setSelectedName(null);
      handleRefresh();
    } catch (err) {
      setDeleteError(err.detail || err.message || "Failed to delete Zone");
    } finally {
      setDeleting(false);
    }
  }

  if (loading && !data) return <div className="center-loading">Loading Zone data...</div>;
  if (!isJuniper && switchportLoading && !switchportData) {
    return <div className="center-loading">Loading Zone data...</div>;
  }

  return (
    <div className="command-configuration">
      {error && <DismissibleError message={error} onDismiss={clearError} />}
      {membershipError && (
        <DismissibleError
          message={membershipError}
          onDismiss={switchportError ? clearSwitchportError : undefined}
        />
      )}

      {formMode ? (
        <ZoneInterfacesFormModal
          key={`${devId}:${vendor}:${formMode}:${selectedName || ""}`}
          devId={devId}
          vendor={vendor}
          mode={formMode}
          editTarget={formMode === "edit" ? selectedZone : null}
          allZones={zones || []}
          wanProtectedInterfaces={wanProtectedInterfaces}
          membersKnown={membershipReady}
          onClose={() => setFormMode(null)}
          onSaved={handleSaved}
        />
      ) : zones === null ? (
        data && (
          <pre>{typeof data.result === "string" ? data.result : JSON.stringify(data.result, null, 2)}</pre>
        )
      ) : (
        <>
          <div className="command-output-title">
            <Edit_Result
              featureName="Zone"
              selectedLabel={selectedZone ? selectedZone.name : ""}
              canEdit={!!selectedZone}
              extraWarning={isJuniper
                ? "Deleting this Zone will also remove Security Policy pairs and NAT rule-set references that use it in the same atomic operation. This may interrupt traffic or management connectivity."
                : "Deleting the Zone will unbind member interfaces and remove all zone-pairs referencing this Zone in a single operation. Interfaces, policy-maps, and ACLs will not be deleted."}
              canDelete={!!selectedZone && !deleting}
              showDeleteConfirm={showDeleteConfirm}
              deleting={deleting}
              deleteError={deleteError} onDismissDeleteError={() => setDeleteError("")}
              onNew={() => setFormMode("create")}
              onEditClick={() => setFormMode("edit")}
              onOpenDeleteConfirm={() => { setDeleteError(""); setShowDeleteConfirm(true); }}
              onCancelDelete={() => setShowDeleteConfirm(false)}
              onConfirmDelete={handleConfirmDelete}
              refreshing={loading || switchportLoading}
              onRefresh={handleRefresh}
            />
          </div>

          {zones.length === 0 ? (
            <div className="config-placeholder">No zones configured</div>
          ) : (
            <div className="security-table-container">
              <table className="security-data-table">
                <thead>
                  <tr>
                    <th>No</th>
                    <th>Zone Name</th>
                    <th>Interface</th>
                    <th>Services</th>
                    <th>Protocol</th>
                  </tr>
                </thead>
                <tbody>
                  {zones.map((zone, index) => (
                    <tr
                      key={`${zone.name}-${index}`}
                      className={`row-clickable ${zone.name === selectedName ? "row-selected" : ""}`}
                      onClick={(event) => setSelectedName(rowClickSelection(event, zone.name, selectedName))}
                      onDoubleClick={rowDoubleClick(!!selectedZone, () => setFormMode("edit"))}
                    >
                      <td>{index + 1}</td>
                      <td>{zone.name}</td>
                      <td>
                        {zone.membersKnown === false ? (
                          "Failed to read"
                        ) : zone.interfaces.length === 0 ? (
                          "-"
                        ) : (
                          <ul>
                            {zone.interfaces.map((iface) => {
                              const isWanProtected = wanProtectedInterfaces.has(iface);
                              return (
                                <li key={iface}>
                                  {iface}
                                  {isWanProtected && (
                                    <span
                                      title="Protected WAN interface cannot be removed from WAN zone"
                                      style={{ marginLeft: "6px" }}
                                    >
                                      🔒
                                    </span>
                                  )}
                                </li>
                              );
                            })}
                          </ul>
                        )}
                      </td>
                      <td>{zone.services.length === 0 ? "-" : zone.services.join(", ")}</td>
                      <td>{zone.protocols.length === 0 ? "-" : zone.protocols.join(", ")}</td>
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
