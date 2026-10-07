import DismissibleError from "../../DismissibleError";
import { useEffect, useState } from "react";
import { runDeviceCommand } from "../../../api/api_devices";
import getDeviceInformation from "../../../hooks/getDeviceInformation";
import RipRouteFormModal from "./RipRouteFormModal";
import { Reload_Result } from "../../commandResult/reload_command_result";

function ensureArray(value) {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

// ป้องกัน React ล่ม ("Objects are not valid as a React child") ถ้า leaf ที่
// คาดว่าเป็น string/number ดันเป็น object แทน (เช่นโครงสร้าง oper GET จริงของ
// Cisco ต่างจากที่ edit-config เขียนไว้ - เจอมาแล้วหลายรอบกับ switchport/
// switchport-config ในเซสชันนี้)
function toText(value) {
  return typeof value === "string" || typeof value === "number" ? String(value) : "";
}

function ipToInt(ip) {
  const parts = (ip || "").trim().split(".");
  if (parts.length !== 4) return null;
  const octets = parts.map(Number);
  if (octets.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;
}

function intToIp(value) {
  return [24, 16, 8, 0].map((shift) => (value >>> shift) & 0xff).join(".");
}

// คำนวณ network address จาก IP + dotted subnet mask ตรงๆ (ip AND mask) - ใช้จับคู่
// "network ที่ตั้งใน RIP config" (Cisco) กับ "interface ที่ IP จริงตกอยู่ใน network
// นั้น" (จาก get_ip_interface_brief) โดยไม่ต้องแปลง prefix ก่อน
function networkOf(ip, subnetDotted) {
  const ipInt = ipToInt(ip);
  const maskInt = ipToInt(subnetDotted);
  if (ipInt === null || maskInt === null) return null;
  return intToIp((ipInt & maskInt) >>> 0);
}

// ---------- Table 1: RIP routes ทั้งหมด (จาก get_routing_table, กรอง protocol=rip) ----------
// โครงสร้างเดียวกับ static_route.jsx (Cisco ietf-routing routing-state, Juniper
// get-route-information route-table) แค่เปลี่ยนตัวกรอง protocol เป็น "rip" แทน
// "static" - ดู static_route.jsx สำหรับที่มาของ path ทั้งหมด (verify แล้วกับ
// Cisco จริง, Junos ยืนยันจาก junos-es-rpc-route.yang) - **บั๊กเดียวกับที่เจอใน
// static_route.jsx/network_status.jsx**: get-route-information เป็น
// operational RPC ไม่มี ".data" คั่นกลาง (ยืนยันจาก curl ตรงๆ) แก้ตามกัน
function extractJuniperRipRoutes(payload) {
  const tables = ensureArray(payload?.["route-information"]?.["route-table"]);
  const routes = [];
  for (const table of tables) {
    for (const rt of ensureArray(table?.rt)) {
      for (const entry of ensureArray(rt?.["rt-entry"])) {
        if ((entry?.["protocol-name"] || "").toLowerCase() !== "rip") continue;
        const nh = ensureArray(entry?.nh)[0] || {};
        routes.push({
          prefix: rt?.["rt-destination"] || "",
          nextHop: nh?.to || "",
          iface: nh?.via || "",
          distance: entry?.preference || "",
          metric: entry?.metric || "",
        });
      }
    }
  }
  return routes;
}

function extractCiscoRipRoutes(payload) {
  const routingState = payload?.data?.["routing-state"];
  const instances = ensureArray(routingState?.["routing-instance"]);
  const routes = [];
  for (const instance of instances) {
    const ribs = ensureArray(instance?.ribs?.rib);
    for (const rib of ribs) {
      const entries = ensureArray(rib?.routes?.route);
      for (const route of entries) {
        // Cisco ietf-routing เก็บ source-protocol เป็น identity-ref ที่มี prefix
        // โมดูลนำหน้าด้วย (ยืนยันจากอุปกรณ์จริง 2026-07-24: OSPF ตอบมาเป็น
        // "ospf:ospfv2" ไม่ใช่ "ospf" เฉยๆ - "static" ไม่มี prefix เพราะนิยามอยู่ใน
        // ietf-routing เอง แต่ rip/ospf มาจาก submodule augment แยกต้องมี prefix)
        // เทียบแบบ "มีคำว่า rip อยู่ใน string" กันเหนียวแทน exact match
        if (!(route?.["source-protocol"] || "").toLowerCase().includes("rip")) continue;
        const nextHop = route?.["next-hop"] || {};
        routes.push({
          prefix: route?.["destination-prefix"] || "",
          nextHop: nextHop?.["next-hop-address"] || "",
          iface: nextHop?.["outgoing-interface"] || "",
          distance: route?.["route-preference"] || "",
          metric: route?.["metric"] || "",
        });
      }
    }
  }
  return routes;
}

function extractRipRoutes(routeTableResult) {
  if (!routeTableResult?.normalized) return null;
  const payload = routeTableResult.result?.payload;
  if (!payload) return null;
  try {
    if (routeTableResult.result?.vendor === "juniper") {
      return extractJuniperRipRoutes(payload);
    }
    return extractCiscoRipRoutes(payload);
  } catch {
    return null;
  }
}

// ---------- Table 2: รายละเอียดอื่นๆ (RIP config summary) ----------
function parseCiscoRip(rip, hasConfig) {
  const redistribute = rip?.redistribute;
  const passive = rip?.["passive-interface"];
  const passiveObject = passive && typeof passive === "object" ? passive : {};
  const passiveInterfaceDefault =
    "default-all-interfaces" in passiveObject || "default" in passiveObject;
  const passiveInterfaces = ensureArray(passiveObject.interfaces ?? passiveObject.interface)
    .map(toText)
    .filter(Boolean);
  // YANG ปัจจุบันเก็บ `no passive-interface` ที่ rip/disable/passive-interface;
  // config รุ่นเก่าบางแบบตอบ disable ซ้อนใต้ passive-interface จึงอ่านทั้งคู่
  const disable = rip?.disable ?? passiveObject.disable;
  const noPassiveInterfaces = ensureArray(disable?.["passive-interface"])
    .map((entry) => toText(entry?.interface ?? entry))
    .filter(Boolean);
  return {
    hasConfig,
    version: toText(rip?.version) || "-",
    // "auto-summary-fix" เป็น leaf ที่ปรากฏเสมอตอนมี RIP process จริง (ยืนยันจาก
    // HQ-R1: "false" string ตรงๆ แม้ตอนสร้างด้วย auto_summary=false) - ต่างจากที่
    // เคยพลาดกับ OSPF's redistribute_static ที่ไม่เคย parse ไว้เลย เลยเพิ่มให้ตรง
    // กับ noAutoSummary field ของฟอร์ม (noAutoSummary = !autoSummary)
    autoSummary: toText(rip?.["auto-summary-fix"]).toLowerCase() === "true",
    redistributeStatic: "static" in (redistribute && typeof redistribute === "object" ? redistribute : {}),
    defaultInformationOriginate: typeof rip === "object" && "default-information" in rip,
    entries: ensureArray(rip?.network).map((n) => toText(n?.ip)).filter(Boolean),
    entryLabel: "Network",
    passiveInterfaceDefault,
    noPassiveInterfaces,
    passiveInterfaces,
  };
}

// เจอบั๊กจริง (2026-07-29): set_rip_routing เดิมไม่เคยผูก export policy ให้
// group เลย - RIP รับ route จาก neighbor ได้ปกติแต่ไม่เคยประกาศ subnet ของ
// ตัวเองออกไปเลยสักเส้น (Junos routing protocol default deny-all export) แก้แล้ว
// ที่ backend โดยผูก "EXPORT-SUBNETS" (term 1: from protocol direct -> accept)
// เป็น baseline เสมอ - redistributeStatic ตอนนี้ไม่ใช่ policy แยกอีกต่อไป (เดิม
// เช็คแค่ว่ามีชื่อ "EXPORT-STATIC" อยู่ใน export list ของ group) แต่เป็น
// "static" อยู่ใน protocol list ของ EXPORT-SUBNETS's term 1 หรือเปล่าแทน (from
// protocol [ direct static ] - รวม term เดียวกันตามที่ user ระบุ) ต้องเปิด
// policy-options/policy-statement มาด้วย (get_rip_information ขยาย filter ให้
// แล้ว) ถึงจะเช็คเนื้อหาจริงได้ - defaultInformationOriginate implement จริง
// แล้วเช่นกัน (เดิม raise ValueError ตายตัว) เช็คจากชื่อ policy "EXPORT-DEFAULT-RIP"
// ตรงๆ ได้เลย (ไม่ต้องดูเนื้อหาข้างใน - แค่มี/ไม่มีก็พอ ไม่มีทางชนกับ policy อื่น)
function parseJuniperRip(configuration) {
  const groups = ensureArray(configuration?.protocols?.rip?.group);
  const group = groups[0] || {};
  const receive = group?.receive;
  const version = receive && typeof receive === "object" && "version-1" in receive ? "1" : "2";
  const exportPolicies = ensureArray(group?.export).map(toText);

  const policyStatements = ensureArray(configuration?.["policy-options"]?.["policy-statement"]);
  const exportSubnets = policyStatements.find((p) => toText(p?.name) === "EXPORT-SUBNETS");
  const terms = ensureArray(exportSubnets?.term);
  const term1 = terms.find((t) => toText(t?.name) === "1") || terms[0];
  const protocolList = ensureArray(term1?.from?.protocol).map(toText);

  return {
    hasConfig: groups.length > 0,
    version,
    autoSummary: false, // Junos ไม่มี auto-summary concept แบบ Cisco (set_rip_routing ปฏิเสธ auto_summary=true ไปแล้วตั้งแต่ฝั่ง backend)
    redistributeStatic: protocolList.includes("static"),
    defaultInformationOriginate: exportPolicies.includes("EXPORT-DEFAULT-RIP"),
    entries: ensureArray(group?.neighbor).map((n) => toText(n?.name)).filter(Boolean),
    entryLabel: "Interface",
  };
}

function parseRipSummary(result) {
  try {
    if (result?.vendor === "juniper") {
      return parseJuniperRip(result?.payload?.data?.configuration);
    }
    // rip เป็น "" (ไม่ใช่ object) เมื่ออุปกรณ์ยังไม่มี RIP process ตั้งค่าไว้เลย -
    // ส่ง {} ให้ parseCiscoRip แทน (defaults เป็นค่าว่าง/ปิดทั้งหมดอยู่แล้ว) แต่แยก
    // hasConfig ไว้ต่างหาก (ต้องรู้ว่า "ยังไม่มี RIP" กับ "มี RIP แต่ parse เป็นค่า
    // ว่างพอดี" ต่างกัน เพื่อโชว์ New เทียบกับ Edit/Delete ให้ถูก)
    const rip = result?.payload?.data?.native?.router?.rip;
    const hasConfig = typeof rip === "object" && rip !== null;
    return parseCiscoRip(hasConfig ? rip : {}, hasConfig);
  } catch {
    return null;
  }
}

// ---------- Table 3: Interface และ IP ที่ตั้งไปใน RIP ----------
// Cisco: rip.network เป็น "network address" (ไม่ใช่ชื่อ interface) - ต้อง
// จับคู่กับ get_ip_interface_brief เอง (หา interface ที่ IP ตกอยู่ใน network
// นั้นจริง) Juniper: group.neighbor เป็น "ชื่อ interface" ตรงๆ อยู่แล้ว (Junos
// เปิด RIP ต่อ interface ไม่ใช่ต่อ network) - จับคู่ตรงชื่อได้เลย
function buildInterfaceRows(summary, vendor, ifaceRows) {
  if (vendor === "juniper") {
    return summary.entries.map((name) => {
      const match = ifaceRows.find((row) => row.name === name);
      const ip = match?.ip && match.ip !== "-" ? match.ip : "";
      const network = ip && match?.subnet ? networkOf(ip, match.subnet) : null;
      return { interface: name, ip: ip || "-", network: network || "-" };
    });
  }
  return summary.entries.map((networkAddr) => {
    const match = ifaceRows.find((row) => {
      if (!row.ip || row.ip === "-" || !row.subnet) return false;
      return networkOf(row.ip, row.subnet) === networkAddr;
    });
    return {
      interface: match?.name || "-",
      ip: match?.ip || "-",
      network: networkAddr,
    };
  });
}

// ---------- Presentation ร่วม (เดิมทั้งหมด แค่รับ summary/routes/ifaceRows ที่
// parse เสร็จแล้วเป็น prop - แยก data-fetching ต่อยี่ห้อไว้ที่ wrapper ด้านล่าง
// เหมือน ospf_route.jsx) ----------
function RipPage({ devId, vendor, summary, routes, ifaceRows, busy, onRefresh, readError = "", onDismissReadError }) {
  const isJuniper = vendor === "juniper";
  const [formOpen, setFormOpen] = useState(false); // toggle "Enable RIP" - ใช้ร่วมกันทั้ง 2 ยี่ห้อ
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState("");

  function handleSaved() {
    onRefresh();
  }

  // RIP เป็น process เดียวทั้งอุปกรณ์ (ไม่มี process-id แยกหลายตัวแบบ OSPF) เลยไม่มี
  // row-selection - toggle ปิด = ผูกกับ process ทั้งก้อนเสมอ - remove_rip_routing
  // ใช้ได้ทั้ง 2 ยี่ห้อแล้ว (ทดสอบจริงกับ Juniper ผ่าน UI นี้เองแล้วด้วย)
  async function handleConfirmDelete() {
    setDeleting(true);
    setDeleteError("");
    try {
      await runDeviceCommand(devId, "remove_rip_routing", {});
      setShowDeleteConfirm(false);
      onRefresh();
    } catch (err) {
      setDeleteError(err.detail || "Failed to remove RIP routing");
    } finally {
      setDeleting(false);
    }
  }

  const interfaceRows = summary ? buildInterfaceRows(summary, vendor, ifaceRows).map((row) => ({
    ...row,
    passive: !isJuniper && (
      summary.passiveInterfaceDefault
        ? !summary.noPassiveInterfaces.includes(row.interface)
        : summary.passiveInterfaces.includes(row.interface)
    ),
  })) : [];

  // sync toggle ให้ตรงกับสถานะจริงเสมอตอนโหลด/รีเฟรช (เหมือน nat.jsx) - เปิดฟอร์ม
  // ให้เองถ้ามี RIP process อยู่แล้ว ไม่ต้องกดเปิดซ้ำ - ใช้ toggle เดียวกันทั้ง 2
  // ยี่ห้อแล้ว (เดิม Juniper ใช้ formMode/New-Edit-Delete แยกต่างหาก ตอนนี้รวมเป็น
  // UI เดียวกับ Cisco ตามที่ user ขอ)
  useEffect(() => {
    if (summary) setFormOpen(summary.hasConfig);
  }, [summary?.hasConfig]);

  function handleToggleClick() {
    if (!formOpen) {
      // ปิด -> เปิด: แค่โชว์ฟอร์มให้กรอก ยังไม่ยิงอะไรจนกว่าจะกด Apply
      setFormOpen(true);
      return;
    }
    if (!summary?.hasConfig) {
      // ฟอร์มเปิดอยู่แต่ยังไม่เคย Apply จริง (ไม่มี RIP process อยู่จริง) - กดปิด
      // ก็แค่ซ่อนฟอร์ม
      setFormOpen(false);
      return;
    }
    // มี RIP process จริงอยู่ - กดปิด = ต้องการรื้อทิ้งจริง กระทบ routing ทันที
    // ต้องยืนยันก่อน
    setShowDeleteConfirm(true);
  }

  return (
    <div className="command-configuration">
      {readError && <DismissibleError message={readError} onDismiss={onDismissReadError} />}
      {summary === null ? (
        <div className="config-placeholder">Failed to parse RIP information</div>
      ) : (
        <>
          <div className="interface-configuration-form">
              <div className="interface-configuration-form-field">
                <label className="data-label" >Enable RIP</label>
                <div className="toggle-switch-container">
                  <input type="checkbox" id="rip-enable-toggle" checked={formOpen} onChange={handleToggleClick} />
                  <label className="toggleSwitch" htmlFor="rip-enable-toggle"></label>
                </div>
              </div>
              {formOpen && (
                <RipRouteFormModal
                  devId={devId}
                  vendor={vendor}
                  currentRule={summary.hasConfig ? summary : null}
                  onSaved={handleSaved}
                />
              )}
          </div>

          {showDeleteConfirm && (
            <div className="modal-overlay" onClick={() => !deleting && setShowDeleteConfirm(false)}>
              <div className="modal-card" onClick={(event) => event.stopPropagation()}>
                <div className="modal-header">
                  <h2>Confirm Disabling RIP</h2>
                  <button
                    type="button"
                    className="modal-close"
                    onClick={() => setShowDeleteConfirm(false)}
                    aria-label="Close"
                    disabled={deleting}
                  >
                    &times;
                  </button>
                </div>
                <p>Are you sure you want to disable all RIP routing (including all configured networks/redistributions)?</p>
                {deleteError && <DismissibleError message={deleteError} onDismiss={() => setDeleteError("")} />}
                <div className="modal-actions">
                  <button
                    type="button"
                    className="btn btn-ghost"
                    onClick={() => setShowDeleteConfirm(false)}
                    disabled={deleting}
                  >
                    Cancel
                  </button>
                  <button type="button" className="btn btn-primary" onClick={handleConfirmDelete} disabled={deleting}>
                    {deleting ? "Disabling..." : "Disable RIP"}
                  </button>
                </div>
              </div>
            </div>
          )}

          {!summary.hasConfig ? null : (
            <>
              <div className="command-output-title">
                All RIP Routes
                <Reload_Result loading={busy} onRefresh={onRefresh} />
              </div>
              {routes === null ? (
                <div className="config-placeholder">Failed to retrieve routing table or not supported on this vendor</div>
              ) : routes.length === 0 ? (
                <div className="config-placeholder">No routes learned via RIP</div>
              ) : (
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Destination</th>
                      <th>Next Hop</th>
                      <th>Exit Interface</th>
                      <th>Distance</th>
                      <th>Metric</th>
                    </tr>
                  </thead>
                  <tbody>
                    {routes.map((route, index) => (
                      <tr key={`${route.prefix}-${index}`}>
                        <td>{route.prefix}</td>
                        <td>{route.nextHop || "-"}</td>
                        <td>{route.iface || "-"}</td>
                        <td>{route.distance || "-"}</td>
                        <td>{route.metric || "-"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}

              {/* "รายละเอียดอื่นๆ" (Version/Redistribute Static/Default-information
              originate) เอาออกจาก Cisco แล้ว - ค่าพวกนี้เป็น field ในฟอร์มด้านบน
              อยู่แล้ว (pre-fill ตรงๆ ตอนมี process อยู่) โชว์ซ้ำเป็น table แยกอีก
              รอบก็ซ้ำซ้อนเปล่าๆ - Juniper ยังต้องมีเพราะฟอร์ม edit ของ Juniper ไม่ได้
              โชว์ inline ตลอด (เปิดเฉพาะกด Edit) */}
              {isJuniper && (
                <>
                  <div className="command-output-title">Other Details</div>
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>RIP Version</th>
                        <th>Redistribute Static</th>
                        {summary.defaultInformationOriginate !== null && <th>Default-information originate</th>}
                      </tr>
                    </thead>
                    <tbody>
                      <tr>
                        <td>{summary.version}</td>
                        <td>{summary.redistributeStatic ? "Enabled" : "Disabled"}</td>
                        {summary.defaultInformationOriginate !== null && (
                          <td>{summary.defaultInformationOriginate ? "Enabled" : "Disabled"}</td>
                        )}
                      </tr>
                    </tbody>
                  </table>
                </>
              )}

              <div className="command-output-title">
                Configured Interfaces and IPs
                <Reload_Result loading={busy} onRefresh={onRefresh} />
              </div>
              {interfaceRows.length === 0 ? (
                <div className="config-placeholder">No {summary.entryLabel} configured in RIP</div>
              ) : (
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Interface</th>
                      <th>IP Address</th>
                      <th>Network</th>
                      {!isJuniper && <th>Passive</th>}
                    </tr>
                  </thead>
                  <tbody>
                    {interfaceRows.map((row, index) => (
                      <tr key={`${row.interface}-${index}`}>
                        <td>{row.interface}</td>
                        <td>{row.ip}</td>
                        <td>{row.network}</td>
                        {!isJuniper && <td>{row.passive ? "Yes" : "No"}</td>}
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </>
          )}
        </>
      )}
    </div>
  );
}

// ---------- Cisco: 1 round-trip เดียว (get_rip_dashboard รวม rip/routes/
// interfaces) ----------
function CiscoRipPage({ devId }) {
  const { data, loading, error, clearError, refetch } = getDeviceInformation(devId, "get_rip_dashboard");

  if (loading && !data) return <div className="center-loading">Loading RIP data...</div>;
  if (error && !data) {
    return <DismissibleError message={error} onDismiss={() => { clearError(); refetch(); }} />;
  }
  if (!data?.normalized) {
    return (
      <div className="command-configuration">
        {data && <pre>{typeof data.result === "string" ? data.result : JSON.stringify(data.result, null, 2)}</pre>}
      </div>
    );
  }

  const result = data.result; // {vendor: "cisco", payload: {...}, interfaces: [...]}
  const summary = parseRipSummary(result);
  const routes = extractRipRoutes({ normalized: true, result });
  const ifaceRows = result.interfaces || [];

  return (
    <RipPage
      devId={devId}
      vendor="cisco"
      summary={summary}
      routes={routes}
      ifaceRows={ifaceRows}
      busy={loading}
      onRefresh={refetch}
      readError={error}
      onDismissReadError={clearError}
    />
  );
}

// ---------- Juniper: คงเดิม 3 query แยก (Junos operational RPC คนละ verb กับ
// get-config เลยรวมเป็น request เดียวไม่ได้แบบ Cisco) ----------
function JuniperRipPage({ devId }) {
  const { data, loading, error, clearError, refetch } = getDeviceInformation(devId, "get_rip_information");
  const {
    data: routeTableData,
    loading: routeTableLoading,
    refetch: refetchRouteTable,
  } = getDeviceInformation(devId, "get_routing_table");
  const {
    data: ifData,
    loading: ifLoading,
    refetch: refetchIf,
  } = getDeviceInformation(devId, "get_ip_interface_brief");

  function handleRefreshAll() {
    refetch();
    refetchRouteTable();
    refetchIf();
  }

  if (loading && !data) return <div className="center-loading">Loading RIP data...</div>;
  if (error && !data) {
    return <DismissibleError message={error} onDismiss={() => { clearError(); refetch(); }} />;
  }
  if (!data?.normalized) {
    return (
      <div className="command-configuration">
        {data && <pre>{typeof data.result === "string" ? data.result : JSON.stringify(data.result, null, 2)}</pre>}
      </div>
    );
  }

  const summary = parseRipSummary(data.result);
  const routes = extractRipRoutes(routeTableData);
  const ifaceRows = ifData?.normalized ? ifData.result : [];

  return (
    <RipPage
      devId={devId}
      vendor="juniper"
      summary={summary}
      routes={routes}
      ifaceRows={ifaceRows}
      busy={loading || routeTableLoading || ifLoading}
      onRefresh={handleRefreshAll}
      readError={error}
      onDismissReadError={clearError}
    />
  );
}

export default function RipRoute({ devId, vendor }) {
  if (vendor === "juniper") return <JuniperRipPage devId={devId} />;
  return <CiscoRipPage devId={devId} />;
}
