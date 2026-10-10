import DismissibleError from "../../DismissibleError";
import { useState } from "react";
import getDeviceInformation from "../../../hooks/getDeviceInformation";
import { runDeviceCommand } from "../../../api/api_devices";
import { normalizeSubnet } from "../../../utils/normalizeSubnet";
import { displayStaticRouteDistance } from "../../../utils/staticRouteDistance";
import StaticRouteFormModal from "./StaticRouteFormModal";
import Edit_Result from "../../commandResult/edit_command_result";

function ensureArray(value) {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

function looksLikeIp(value) {
  return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(value || "");
}

// ตาราง "static route ทุกตัว (config จริง ไม่ว่าจะ active หรือไม่)" - อ่านจาก
// get_static_route_configuration (native/ip/route ตรงๆ - เดียวกับที่
// set_static_route/remove_static_route เขียน/ลบ) ต่างจาก extractStaticRoutes
// (ตัวเดิม) ที่อ่านจาก RIB ที่ active จริงเท่านั้น (get_routing_table) - เจอจริงบน
// HQ-R1 ว่า route ที่ next-hop resolve ไม่ได้ (ไม่ใช่ path ตรงๆ ต้องผ่าน default
// route เอง) จะไม่โผล่ใน RIB เลยแม้จะตั้งค่าไว้จริงใน config - ตารางนี้เก็บไว้ให้
// เห็นว่า "ตั้งอะไรไว้บ้าง" แยกจาก "อะไร active อยู่จริง" ของตารางเดิม
function extractConfiguredCiscoRoutes(payload) {
  const entries = ensureArray(payload?.data?.native?.ip?.route?.["ip-route-interface-forwarding-list"]);
  const routes = [];
  for (const entry of entries) {
    const prefix = entry?.prefix || "";
    const subnet = normalizeSubnet(entry?.mask);
    const prefixCidr = prefix && subnet ? `${prefix}/${subnet.prefix}` : prefix;
    for (const fwd of ensureArray(entry?.["fwd-list"])) {
      const target = fwd?.fwd || "";
      routes.push({
        prefix: prefixCidr,
        nextHop: looksLikeIp(target) ? target : "",
        iface: looksLikeIp(target) ? "" : target,
        distance: fwd?.metric || "",
      });
    }
  }
  return routes;
}

// Junos: routing-options/static/route[name]/next-hop (list) + preference/
// metric-value - ตรงกับที่ set_static_route เขียน (ดู juniper_junos.py) ยังไม่เคย
// verify กับอุปกรณ์ Junos จริงในเซสชันนี้ (ไม่มีเครื่องให้ทดสอบ) - best-effort
// ตามโครงสร้างที่เขียนเอง เหมือน extractJuniperStaticRoutes เดิม
function extractConfiguredJuniperRoutes(payload) {
  const entries = ensureArray(payload?.data?.configuration?.["routing-options"]?.static?.route);
  const routes = [];
  for (const entry of entries) {
    const name = entry?.name || "";
    const distance = entry?.preference?.["metric-value"] || "";
    const nextHops = ensureArray(entry?.["next-hop"]);
    if (nextHops.length === 0) {
      routes.push({ prefix: name, nextHop: "", iface: "", distance });
      continue;
    }
    for (const nh of nextHops) {
      const target = typeof nh === "string" ? nh : "";
      routes.push({
        prefix: name,
        nextHop: looksLikeIp(target) ? target : "",
        iface: looksLikeIp(target) ? "" : target,
        distance,
      });
    }
  }
  return routes;
}

// VRP ใช้ staticrt/srRoutes ทั้งตอนอ่าน configuration และ routing table
// (get_routing_table ของ Huawei query static route โดยตรง) จึงใช้ตัวแปลงเดียวกัน
// โดย maskLength เป็น CIDR อยู่แล้ว ไม่ต้องแปลง netmask แบบ Cisco.
function extractHuaweiStaticRoutes(payload) {
  const entries = ensureArray(payload?.data?.staticrt?.staticrtbase?.srRoutes?.srRoute);
  return entries.map((entry) => ({
    prefix: entry?.prefix !== undefined && entry?.maskLength !== undefined
      ? `${entry.prefix}/${entry.maskLength}` : entry?.prefix || "",
    nextHop: entry?.nexthop || "",
    iface: entry?.ifName || "",
    distance: entry?.preference || "",
    metric: entry?.cost || "",
  }));
}

function extractConfiguredStaticRoutes(payload, vendor) {
  try {
    if (vendor === "juniper") return extractConfiguredJuniperRoutes(payload);
    if (vendor === "huawei") return extractHuaweiStaticRoutes(payload);
    return extractConfiguredCiscoRoutes(payload);
  } catch {
    return null;
  }
}

// get_routing_table ไม่มี normalizer เฉพาะสำหรับ "static route อย่างเดียว" -
// normalize_generic (ฝั่ง backend) คืน full RIB แบบ nested JSON ที่ field ยังเป็น
// ชื่อดิบของแต่ละยี่ห้ออยู่ (ไม่ unify เหมือน normalize_interfaces/normalize_arp)
// เพราะยังไม่เคยทดสอบกับอุปกรณ์ Juniper/Huawei จริงว่าโครงสร้างตรงกับ schema ที่
// อ่านมาไหม (บทเรียนจาก arp-entry/arp-oper ที่เดาผิดมาแล้วรอบนึง) - เลย filter/
// แปลงเป็นตาราง static route เฉพาะฝั่ง frontend ตรงนี้ที่เดียว จำกัดขอบเขตแค่หน้า
// นี้หน้าเดียว ยืนยันแล้วว่า path นี้ตรงกับ Cisco จริง (ดู HANDOFF.md) ยี่ห้ออื่นที่
// โครงสร้างไม่ตรง (เช่น Huawei ที่ get_routing_table คืนแค่ static routes อยู่แล้ว
// จาก YANG module คนละตัว) จะ extract ไม่ได้แล้ว fallback ไปโชว์ JSON ดิบแทน
// Junos: get_routing_table ใช้ RPC เฉพาะของ Junos เอง (get-route-information -
// ไม่ใช่ ietf-routing แบบ Cisco เลย) โครงสร้างมาตรฐานของ Junos XML API สำหรับ
// "show route": route-information/route-table/rt (key rt-destination รวม
// prefix length มาให้แล้ว)/rt-entry (protocol-name/preference/metric)/nh
// (to/via) - ยืนยัน field ทั้งหมดจาก junos-es-rpc-route.yang:1828-1934 (list
// route-table -> list rt -> list rt-entry -> list nh) กรองเอาเฉพาะ protocol
// "Static" (Junos ใช้ตัวพิมพ์ใหญ่นำ - เทียบแบบ case-insensitive กันเหนียว) -
// **บั๊กที่เจอจริงตอนทดสอบผ่าน browser (dashboard/network_status.jsx ใช้ path
// เดียวกันนี้เจอก่อน)**: get-route-information เป็น operational RPC ไม่มี
// ".data" คั่นกลางเหมือน get-config (ยืนยันจาก curl ตรงๆ) path เดิมมี ".data"
// เกินมาทำให้ extract ได้ [] ว่างเปล่าตลอด
function extractJuniperStaticRoutes(payload) {
  const tables = ensureArray(payload?.["route-information"]?.["route-table"]);
  const routes = [];
  for (const table of tables) {
    for (const rt of ensureArray(table?.rt)) {
      for (const entry of ensureArray(rt?.["rt-entry"])) {
        if ((entry?.["protocol-name"] || "").toLowerCase() !== "static") continue;
        // เก็บทุก nh (ไม่ใช่แค่ตัวแรก) - route ที่มีหลาย next-hop ต้องเทียบสถานะ
        // ของแถว config ได้ครบทุกตัว (ดู isRouteActive)
        const nextHops = ensureArray(entry?.nh);
        for (const nh of nextHops.length > 0 ? nextHops : [{}]) {
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
  }
  return routes;
}

function extractStaticRoutes(payload, vendor) {
  if (vendor === "huawei") {
    try {
      return extractHuaweiStaticRoutes(payload).map((route) => ({ ...route, protocol: "Static" }));
    } catch {
      return null;
    }
  }
  if (vendor === "juniper") {
    try {
      return extractJuniperStaticRoutes(payload);
    } catch {
      return null;
    }
  }
  try {
    const routingState = payload?.data?.["routing-state"];
    const instances = ensureArray(routingState?.["routing-instance"]);
    const routes = [];
    for (const instance of instances) {
      const ribs = ensureArray(instance?.ribs?.rib);
      for (const rib of ribs) {
        const entries = ensureArray(rib?.routes?.route);
        for (const route of entries) {
          if (route?.["source-protocol"] !== "static") continue;
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
  } catch {
    return null;
  }
}

function routeKey(route) {
  return `${route.prefix}::${route.nextHop}::${route.iface}`;
}

// สถานะของแถว config แต่ละแถว = มี route เดียวกันอยู่ใน RIB (get_routing_table)
// หรือไม่ - RIB มีแค่ route ที่ active จริง route ที่ตั้งไว้แต่ next-hop resolve
// ไม่ได้/ขาออก down จะไม่อยู่ในนั้น (ดูคอมเมนต์ extractConfiguredCiscoRoutes)
// เทียบ prefix ก่อน แล้วเทียบ next hop ถ้าแถว config ระบุไว้ ไม่งั้นเทียบขาออก
// (route แบบ interface) - route ที่ไม่มีทั้งสองอย่าง (เช่น discard ของ Junos)
// เทียบแค่ prefix
function isRouteActive(configured, activeRoutes) {
  return activeRoutes.some((active) => {
    if (active.prefix !== configured.prefix) return false;
    if (configured.nextHop) return active.nextHop === configured.nextHop;
    if (configured.iface) return active.iface === configured.iface;
    return true;
  });
}

// Huawei: get_routing_table ของ VRP query static route จาก config ตรง ๆ (srRoutes
// ตัวเดียวกับ get_static_route_configuration) ไม่ใช่ RIB จึงบอกไม่ได้ว่า route
// ไหน active - คืน null = ไม่ทราบสถานะ แทนที่จะโชว์เขียวทุกแถวแบบหลอก ๆ
function resolveRouteStatus(configured, activeRoutes, vendor) {
  if (vendor === "huawei" || !activeRoutes) return null;
  return isRouteActive(configured, activeRoutes) ? "up" : "down";
}

function RouteStatusDot({ status }) {
  if (!status) {
    return <span className="route-status-dot route-status-unknown" title="Status not available" aria-label="Status not available" />;
  }
  const label = status === "up" ? "Up (active in routing table)" : "Down (not in routing table)";
  return <span className={`route-status-dot route-status-${status}`} title={label} aria-label={label} />;
}

export default function StaticRoute({ devId, vendor }) {
  const { data, loading, error, clearError, refetch } = getDeviceInformation(devId, "get_routing_table");
  const {
    data: configData,
    loading: configLoading,
    refetch: refetchConfig,
  } = getDeviceInformation(devId, "get_static_route_configuration");
  const [showForm, setShowForm] = useState(false);
  const [formMode, setFormMode] = useState("create");
  const [selectedKey, setSelectedKey] = useState(null);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState("");

  function handleSaved() {
    setShowForm(false);
    setSelectedKey(null);
    refetch();
    refetchConfig();
  }

  function handleNew() {
    setFormMode("create");
    setShowForm(true);
  }

  function handleEdit() {
    if (!selectedKey) return;
    setFormMode("edit");
    setShowForm(true);
  }

  async function handleConfirmDelete(route) {
    const [prefix, mask] = (route.prefix || "").split("/");
    setDeleting(true);
    setDeleteError("");
    try {
      const removeParameters = { prefix, mask: Number(mask) };
      // Huawei ระบุ next_hop ตอนลบ static route; ถ้าข้อมูลเก่าไม่มีค่านี้ต้องหยุด
      // ก่อนยิง RPC เพื่อไม่ให้ VRP ตอบ validation error. สองยี่ห้ออื่นคง payload เดิม.
      if (vendor === "huawei") {
        if (!route.nextHop) throw new Error("Next Hop not found for the selected static route");
        removeParameters.next_hop = route.nextHop;
      }
      await runDeviceCommand(devId, "remove_static_route", removeParameters);
      setShowDeleteConfirm(false);
      setSelectedKey(null);
      refetch();
      refetchConfig();
    } catch (err) {
      setDeleteError(err.detail || "Failed to delete static route");
    } finally {
      setDeleting(false);
    }
  }

  // รอทั้ง 2 query ให้เสร็จก่อนโชว์อะไรเลย (ไม่ใช่แค่ query แรก) - กัน "ตารางที่ 2
  // โผล่ทีหลัง" เพราะ get_routing_table/get_static_route_configuration resolve
  // ไม่พร้อมกัน (คนละ round-trip คนละเวลา) เห็นเป็นหน้าเดียวพร้อมกันทีเดียวแทน
  if ((loading && !data) || (configLoading && !configData)) {
    return <div className="center-loading">Loading routing table...</div>;
  }

  // RIB ไม่แสดงเป็นตารางแยกแล้ว - ใช้แค่หาสถานะ up/down ของแต่ละแถวในตาราง config
  const payload = data?.normalized ? data.result?.payload : null;
  const activeRoutes = payload ? extractStaticRoutes(payload, data.result?.vendor) : null;
  const statusVendor = data?.result?.vendor || vendor;

  const configPayload = configData?.normalized ? configData.result?.payload : null;
  const configuredRoutes = configPayload
    ? extractConfiguredStaticRoutes(configPayload, configData.result?.vendor)
    : null;
  const selectedRoute = configuredRoutes?.find((r) => routeKey(r) === selectedKey) || null;

  return (
    <div className="command-configuration">
      {error && <DismissibleError message={error} onDismiss={clearError} />}

      {showForm ? (
        <StaticRouteFormModal
          devId={devId}
          vendor={vendor}
          mode={formMode}
          editTarget={formMode === "edit" ? selectedRoute : null}
          onClose={() => setShowForm(false)}
          onSaved={handleSaved}
        />
      ) : (
        <>
          <div className="command-output-title">
            <Edit_Result
              featureName="static route"
              selectedLabel={selectedRoute ? `${selectedRoute.prefix} (next hop ${selectedRoute.nextHop || selectedRoute.iface})` : ""}
              canEdit={!!selectedKey}
              canDelete={!!selectedKey}
              showDeleteConfirm={showDeleteConfirm}
              deleting={deleting}
              deleteError={deleteError} onDismissDeleteError={() => setDeleteError("")}
              onNew={handleNew}
              onEditClick={handleEdit}
              onOpenDeleteConfirm={() => setShowDeleteConfirm(true)}
              onCancelDelete={() => setShowDeleteConfirm(false)}
              onConfirmDelete={() => handleConfirmDelete(selectedRoute)}
              refreshing={configLoading || loading}
              onRefresh={() => {
                refetchConfig();
                refetch();
              }}
            />
          </div>

          {configuredRoutes === null ? (
            configData && (
              <pre>{typeof configData.result === "string" ? configData.result : JSON.stringify(configData.result, null, 2)}</pre>
            )
          ) : configuredRoutes.length === 0 ? (
            <div className="config-placeholder">No static routes configured</div>
          ) : (
            <table className="data-table static-route-table">
              <thead>
                <tr>
                  <th className="route-status-col">Status</th>
                  <th>Destination</th>
                  <th>Next Hop</th>
                  <th>Exit Interface</th>
                  <th>Distance</th>
                </tr>
              </thead>
              <tbody>
                {configuredRoutes.map((route, index) => {
                  const key = routeKey(route);
                  return (
                    <tr
                      key={`${key}-${index}`}
                      className={`row-clickable ${key === selectedKey ? "row-selected" : ""}`}
                      onClick={() => setSelectedKey((prev) => (prev === key ? null : key))}
                    >
                      <td className="route-status-col">
                        <RouteStatusDot status={resolveRouteStatus(route, activeRoutes, statusVendor)} />
                      </td>
                      <td>{route.prefix}</td>
                      <td>{route.nextHop || "-"}</td>
                      <td>{route.iface || "-"}</td>
                      <td>{displayStaticRouteDistance(route.distance, configData.result?.vendor || vendor)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </>
      )}
    </div>
  );
}
