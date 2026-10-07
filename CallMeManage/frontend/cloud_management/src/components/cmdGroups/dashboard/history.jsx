import DismissibleError from "../../DismissibleError";
import { useCallback, useEffect, useReducer, useRef, useState } from "react";
import { getDeviceHistory } from "../../../api/api_devices";
import { formatDate } from "../../../utils/formatDate";
import { Reload_Result } from "../../commandResult/reload_command_result";
import { Pagination } from "../../Pagination";
import { describeNatPoolChange, describeNatPoolRemoval } from "../addresses/addressPoolHistory";

// จำนวนแถวต่อ 1 หน้า - ต้องตรงกับ HISTORY_PAGE_SIZE ฝั่ง backend (device_router.py)
// ใช้คำนวณเลขลำดับ (No) ให้นับต่อเนื่องข้ามหน้าเท่านั้น ไม่ได้ส่งค่านี้ไป backend
const HISTORY_PAGE_SIZE = 80;

function parseDetail(detail) {
  if (!detail) return {};
  try {
    const parsed = JSON.parse(detail);
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

function ifName(p) {
  return `${p.interface_type || ""}${p.interface_id || ""}`;
}

// คำสั่งที่รู้จัก -> ประโยคภาษาพูดอ่านง่าย (ครอบคลุมกลุ่ม Interface/DHCP/Routing/
// NAT/Firewall ที่ user ยกตัวอย่างมา) - ชื่อ parameter ตรงกับ signature จริงใน
// vendor_translators/*.py (cisco/juniper ใช้ชื่อ param เดียวกันเป๊ะสำหรับคำสั่ง
// พวกนี้ ตรวจสอบแล้วก่อนเขียน ไม่ใช่เดา) - คำสั่งที่ไม่ได้ลิสต์ไว้ตกไปใช้
// paramsToLines() แทน (ไม่มีทางเห็น raw "{...}" JSON อีกต่อไปไม่ว่าคำสั่งไหน)
const DESCRIBERS = {
  update_security_zone: (p) => `Update Security Zone "${p.zone_name}": ${(p.changes || []).join("; ")}`,
  set_interface_static_ip: (p) => `Configure static IP ${p.ip}/${p.mask} on Interface ${ifName(p)}`,
  set_interface_ip_dhcp: (p) => `Configure Interface ${ifName(p)} to receive IP via DHCP`,
  set_sub_interface_ip: (p) => `Create Sub-interface ${ifName(p)}.${p.vlan_id} with IP ${p.ip}/${p.prefix}`,
  set_interface_vlan: (p) => `Configure VLAN Interface Vlan${p.vlan_id} with IP ${p.ip}/${p.mask}`,
  clear_interface_ip: (p) => `Clear IP address of Interface ${ifName(p)}`,
  remove_interface_unit: (p) => `Delete Sub-interface ${ifName(p)}.${p.unit}`,
  set_dhcp_pool: (p) => `Create DHCP Pool "${p.name}" ${p.network}${p.gateway ? ` (Gateway ${p.gateway})` : ""}`,
  remove_dhcp_pool: (p) => `Delete DHCP Pool "${p.name}"`,
  set_dhcp_relay: (p) => `Configure DHCP Relay on Interface ${ifName(p)} to ${p.helper_ip}`,
  remove_dhcp_relay: (p) => `Delete DHCP Relay on Interface ${ifName(p)}`,
  set_dhcp_server_interface: (p) => `Bind DHCP Server to Interface ${ifName(p)}`,
  remove_dhcp_server_interface: (p) => `Unbind DHCP Server from Interface ${ifName(p)}`,
  set_hostname: (p) => `Change device Hostname to "${p.hostname}"`,
  // replace_prefix มีเฉพาะตอน Huawei แก้ไข route เดิม (ลบ+สร้างใน RPC เดียว) -
  // Cisco/Juniper ไม่เคยส่งคีย์นี้จึงได้ข้อความเดิมทุกกรณีเหมือนก่อนหน้านี้
  set_static_route: (p) =>
    p.replace_prefix
      ? `Edit Static Route ${p.replace_prefix}/${p.replace_mask} to ${p.prefix}/${p.mask} via ${p.next_hop || ifName(p)}`
      : `Add Static Route to ${p.prefix}/${p.mask} via ${p.next_hop || ifName(p)}`,
  remove_static_route: (p) => `Delete Static Route ${p.prefix}/${p.mask}`,
  set_rip_routing: (p) => `Enable RIP Version ${p.version} on ${(Array.isArray(p.networks) ? p.networks : [p.networks]).filter(Boolean).join(", ")}`,
  remove_rip_routing: () => `Disable RIP Routing`,
  set_rip_redistribute_static: (p) => `${p.enabled === false ? "Disable" : "Enable"} Redistribute Static into RIP`,
  create_nat_pool: describeNatPoolChange,
  remove_nat_pool: describeNatPoolRemoval,
  remove_nat_policy: (p) => {
    const ifaces = Array.isArray(p.interfaces) ? p.interfaces.filter(Boolean) : [];
    return `Disable NAT "${p.name}"` + (ifaces.length ? ` (remove nat from ${ifaces.join(", ")})` : "");
  },
  // (ระลอก C3) 1 แถวนี้แทน 12-20 คำสั่งเดิม จึงต้องบอกให้ครบว่าอนุญาตวงไหนออกทางขาไหน
  create_nat_policy: (p) => {
    const scopes = Array.isArray(p.source_scopes) ? p.source_scopes : [p.source_scopes];
    const inside = Array.isArray(p.inside_interfaces) ? p.inside_interfaces : [];
    const via = `${p.via_type || ""}${p.via_id || ""}`;
    const target = p.translate_mode === "pool" ? `NAT pool "${p.pool_name}"` : `IP of ${via}`;
    return (
      `Configure NAT "${p.name}" - route ${scopes.filter(Boolean).join(", ") || "any"} to Internet via ${target}` +
      (inside.length ? ` (inside: ${inside.join(", ")})` : "")
    );
  },
  // Cisco และ Juniper ใช้ parameter คนละรูปแบบ จึงเลือกข้อความตาม rule_name
  set_static_nat: (p) => p.rule_name ? `Configure Static NAT "${p.rule_name}" ${p.destination_address} ↔ ${p.local_address} (Zone ${p.from_zone})` : `Configure Static NAT "${p.name}" ${p.local_ip} ↔ ${p.global_ip}`,
  set_port_forward: (p) => p.rule_name ? `Configure Port Forward "${p.rule_name}" ${p.destination_address}:${p.destination_port} → ${p.local_address}:${p.local_port} (Zone ${p.from_zone})` : `Configure Port Forward "${p.name}" ${(p.protocol || "").toUpperCase()} ${p.global_ip}:${p.global_port} → ${p.local_ip}:${p.local_port}`,
  create_firewall_policy: (p) => `Create Firewall Policy "${p.name}" (${p.source_zone} → ${p.destination_zone}: ${p.action})`,
};

const ACTION_VERBS = { set: "Set", create: "Create", remove: "Remove", clear: "Clear", apply: "Apply" };

function humanizeAction(action) {
  const parts = action.split("_");
  const verb = ACTION_VERBS[parts[0]] || parts[0];
  const noun = (ACTION_VERBS[parts[0]] ? parts.slice(1) : parts).join(" ");
  return `${verb} ${noun}`.trim();
}

// พารามิเตอร์ที่เป็นข้อมูลชุดเดียวกันในความหมาย (คนละ key แต่บอกเรื่องเดียวกัน) -
// ยุบรวมเป็นบรรทัดเดียวก่อนแสดงผล แทนการโชว์แยกชิ้นส่วนแบบ "interface_type: Gi",
// "interface_id: 1" คนละบรรทัดที่อ่านไม่ต่อกัน (ดู acceptance criteria ข้อ 1.3) -
// เช็คตามลำดับนี้ก่อนเสมอ ก่อนจะเอา key ที่เหลือไปแสดงแบบ key:value เดี่ยวๆ ต่อ
const COMPOSITE_FIELDS = [
  { keys: ["interface_type", "interface_id"], label: "Interface", format: (p) => ifName(p) },
  { keys: ["prefix", "mask"], label: "Destination", format: (p) => `${p.prefix}/${p.mask}` },
  { keys: ["prefix", "wildcard"], label: "Network", format: (p) => `${p.prefix} wildcard ${p.wildcard}` },
  { keys: ["network", "gateway"], label: "DHCP Network", format: (p) => `${p.network} (Gateway ${p.gateway})` },
  { keys: ["local_ip", "global_ip"], label: "NAT Mapping", format: (p) => `${p.local_ip} ↔ ${p.global_ip}` },
  { keys: ["source_zone", "destination_zone"], label: "Zone", format: (p) => `${p.source_zone} → ${p.destination_zone}` },
];

function prettifyKey(key) {
  return key
    .split("_")
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ");
}

// (bug 75) เดิม array ถูก join ตรง ๆ ซึ่งพังทันทีถ้าสมาชิกเป็น object - replace_ospf_process
// ส่ง networks เป็น [{network, wildcard, area}] ผู้ใช้จึงเห็น "[object Object], [object
// Object], ..." อ่านไม่ออกเลยว่าตั้ง network อะไรไปบ้าง ทั้งที่นี่คือประวัติแถวเดียวที่แทน
// 12 คำสั่ง จึงยิ่งต้องอ่านรู้เรื่อง - แก้ที่นี่ที่เดียวครอบทุกคำสั่งที่ส่ง array ของ object
function formatValue(value) {
  if (Array.isArray(value)) {
    return value
      .map((item) =>
        item !== null && typeof item === "object" ? Object.values(item).join(" ") : String(item)
      )
      .join(" · ");
  }
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (value !== null && typeof value === "object") return Object.values(value).join(" ");
  return String(value);
}

// ยุบ composite field ก่อน แล้วค่อยแปลง key ที่เหลือเป็น {label, value}[] - ใช้กับ
// คำสั่งที่ไม่มี DESCRIBER เฉพาะ (ยังมีอีกหลายสิบคำสั่งในระบบที่ไม่ได้ลิสต์ไว้ใน
// DESCRIBERS) แทนการโชว์ JSON ดิบหรือ string ต่อกันยาวด้วย " · " แบบเดิม
function paramsToLines(params) {
  const remaining = { ...params };
  const lines = [];
  for (const composite of COMPOSITE_FIELDS) {
    if (composite.keys.every((key) => remaining[key] !== undefined && remaining[key] !== null && remaining[key] !== "")) {
      lines.push({ label: composite.label, value: composite.format(remaining) });
      composite.keys.forEach((key) => delete remaining[key]);
    }
  }
  Object.entries(remaining)
    .filter(([, value]) => value !== null && value !== undefined && value !== "")
    .forEach(([key, value]) => lines.push({ label: prettifyKey(key), value: formatValue(value) }));
  return lines;
}

// Only backend-recorded transactions are grouped; timestamps do not prove atomicity.
// ชุดคำสั่งที่ยิงผ่าน /transaction ถูก commit ครั้งเดียวบนอุปกรณ์ และ backend
// บันทึกเป็นประวัติ **แถวเดียว** ที่มีทุก step อยู่ใน detail.steps (ดู
// run_device_transaction ใน device_router.py) - ต่างจากการยิงทีละคำสั่งผ่าน
// /command ที่ได้แถวละคำสั่งจริงๆ ความต่างนี้คือสิ่งที่ทำให้หน้าประวัติใช้ตรวจได้
// ว่าอันไหน atomic จริง จึงห้ามยุบสองกรณีนี้เข้าหากัน
function transactionSteps(row) {
  const parsed = parseDetail(row.his_action_detail);
  return Array.isArray(parsed.steps) && parsed.steps.length > 0 ? parsed.steps : null;
}

// Summarize one recorded Juniper transaction, never infer boundaries from time.
// This is a display model only; the original ordered steps stay in the database.
function summarizeZoneTransaction(row) {
  const steps = transactionSteps(row);
  if (!steps) return null;
  const changes = new Map();
  let zoneName = null;
  function add(label, values) {
    if (!Array.isArray(values) || values.some((value) => typeof value !== "string" || !value)) return false;
    if (values.length) changes.set(label, [...new Set([...(changes.get(label) || []), ...values])]);
    return true;
  }
  for (const step of steps) {
    const p = step?.parameters;
    if (!p || typeof p.zone_name !== "string" || !p.zone_name) return null;
    if (zoneName !== null && zoneName !== p.zone_name) return null;
    zoneName = p.zone_name;
    const iface = typeof p.interface_type === "string" && typeof p.interface_id === "string"
      ? ifName(p) : "";
    switch (step.command) {
      case "set_security_zone":
        if (!add("Add Zone Services", p.allowed_services ?? []) ||
            !add("Add Zone Protocols", p.allowed_protocols ?? [])) return null;
        // Do not hide fields from API callers outside the Zone form.
        if (Object.keys(p).some((key) => !["zone_name", "allowed_services", "allowed_protocols"].includes(key))) return null;
        break;
      case "apply_zone_member":
      case "remove_zone_member":
        if (!iface || !add(step.command === "apply_zone_member" ? "Add Interface Member" : "Remove Interface Member", [iface])) return null;
        break;
      case "remove_security_zone_service":
        if (!add("Remove Zone Services", [p.service])) return null;
        break;
      case "remove_security_zone_protocol":
        if (!add("Remove Zone Protocols", [p.protocol])) return null;
        break;
      case "remove_zone_interface_service":
        if (!iface || !add(`Remove Services from ${iface}`, [p.service])) return null;
        break;
      case "remove_zone_interface_protocol":
        if (!iface || !add(`Remove Protocols from ${iface}`, [p.protocol])) return null;
        break;
      default:
        return null;
    }
  }
  const descriptions = [...changes].map(([label, values]) => `${label}: ${values.join(", ")}`);
  if (!descriptions.length) return null;
  return {
    ...row,
    his_action: "update_security_zone",
    his_action_detail: JSON.stringify({zone_name: zoneName, changes: descriptions}),
  };
}

// แตกเป็น pseudo-row หน้าตาเหมือนแถวปกติทุกประการ (his_action + his_action_detail)
// เพื่อให้ badge/renderActionDetail ที่มีอยู่แล้วแสดงผลต่อได้โดยไม่ต้องรู้จัก
// transaction เลย - ทั้งชุดใช้ his_action_time เดียวกันเพราะ commit ครั้งเดียว
function expandTransaction(row) {
  return transactionSteps(row).map((step, index) => ({
    ...row,
    his_id: `${row.his_id}#${index}`,
    his_action: step?.command || row.his_action,
    his_action_detail: JSON.stringify(step?.parameters ?? {}),
  }));
}

function groupHistoryRows(rows) {
  // rows จาก backend เรียง desc (ใหม่สุดก่อน - ดู list_history_by_device) - พลิก
  // เป็น asc (เก่าสุดก่อน) ชั่วคราวให้ตรงกับลำดับที่ฟอร์มยิงจริงก่อน เดินหาคู่ได้
  // ง่ายกว่า desc ที่คำสั่งตามหลัง (dhcp) จะโผล่มา"ก่อน"คำสั่งนำ (interface) ในลิสต์
  const asc = [...rows].reverse();
  const groups = [];
  let i = 0;
  while (i < asc.length) {
    const row = asc[i];
    // ชุด transaction เป็น "กลุ่มปิด" - ไม่เอาไปจับคู่ตาม timestamp กับแถวข้างเคียง
    // เพราะขอบเขตของชุดมาจาก backend จริงๆ ไม่ใช่การเดาจากเวลา
    if (transactionSteps(row)) {
      const zoneUpdate = summarizeZoneTransaction(row);
      groups.push(zoneUpdate ? [zoneUpdate] : expandTransaction(row));
      i += 1;
    } else {
      groups.push([row]);
      i += 1;
    }
  }
  return groups.reverse(); // กลับเป็น desc (ใหม่สุดก่อน) สำหรับแสดงผล
}

// แสดงผล 1 action ต่อ 1 block เสมอ (เรียงแนวตั้งตามลำดับที่เกิดขึ้นจริงในกลุ่ม -
// combo[0] คือคำสั่งแรกที่ยิง) แทนการมัดหลายคำสั่งรวมเป็นประโยคเดียวแบบเดิม - ให้
// ตรงกับ badge ที่ก็เรียงแนวตั้งเป็นรายการเดียวกัน (ดู acceptance criteria ข้อ 1
// "Badge ลงมาเป็นแนวตั้ง และพารามิเตอร์...ถูกยุบรวมแสดงผลในบรรทัดเดียว")
function renderActionDetail(row) {
  const params = parseDetail(row.his_action_detail);
  const describer = DESCRIBERS[row.his_action];
  if (describer) {
    try {
      return <div className="history-detail-sentence">{describer(params)}</div>;
    } catch {
      /* param ไม่ครบ/รูปแบบไม่ตรงคาด - fallback ไปใช้ generic grid แทน */
    }
  }
  const lines = paramsToLines(params);
  if (lines.length === 0) {
    return <div className="history-detail-sentence">{humanizeAction(row.his_action)}</div>;
  }
  return (
    <div className="history-detail-block">
      <div className="history-detail-sentence">{humanizeAction(row.his_action)}</div>
      <div className="detail-grid history-detail-grid">
        {lines.map(({ label, value }) => (
          <div className="detail-item" key={label}>
            <span className="label">{label}</span>
            <span className="value">{value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// เก็บ "ชุดข้อมูลที่เคยโหลดมาแล้ว" (stack) + "อยู่ชุดไหนตอนนี้" (index)
// pattern เดียวกับ Devices.jsx - กด "ก่อนหน้า" อ่านจาก stack ใน memory ไม่ต้องยิง request ใหม่
function navReducer(state, action) {
  switch (action.type) {
    case "reset":
      return { stack: [], index: 0 };
    case "set_page": {
      // วางชุดข้อมูลที่ index ที่กำหนด แล้วตัดชุดถัดไปที่เคย cache ไว้ทิ้ง (cursor อาจไม่ตรงแล้ว)
      const stack = state.stack.slice(0, action.index);
      stack[action.index] = action.page;
      return { stack, index: action.index };
    }
    case "go_to_index":
      // เคยโหลดชุดนี้ไว้แล้วใน stack แค่ขยับตำแหน่ง ไม่ต้อง fetch ใหม่
      return { ...state, index: action.index };
    default:
      return state;
  }
}

export default function History({ devId }) {
  const [nav, dispatch] = useReducer(navReducer, { stack: [], index: 0 });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const cancelledRef = useRef(false);   // true เมื่อออกจาก component/สลับอุปกรณ์ -> ทิ้งผลลัพธ์ที่ค้างอยู่
  const prefetchRef = useRef(null);     // ชุดถัดไปที่แอบโหลดล่วงหน้าไว้ { afterHisId, promise }

  const currentPage = nav.stack[nav.index] || null;
  const data = currentPage ? currentPage.items : null;

  // ขอประวัติ 1 ชุดจาก backend ด้วย cursor ที่กำหนด (afterHisId=null คือชุดแรกสุด = ใหม่สุด)
  const fetchPage = useCallback(
    async (afterHisId) => {
      const result = await getDeviceHistory(devId, afterHisId);
      return { items: result.items || [], hasNext: result.has_next };
    },
    [devId]
  );

  // แอบโหลดชุดถัดไปเงียบ ๆ ไว้ล่วงหน้า ให้กด "ถัดไป" แล้วไม่ต้องรอ
  const prefetchNext = useCallback(
    (page) => {
      if (!page || !page.hasNext || page.items.length === 0) return;
      const afterHisId = page.items[page.items.length - 1].his_id;
      if (prefetchRef.current && prefetchRef.current.afterHisId === afterHisId) return; // เคย prefetch แล้ว
      prefetchRef.current = {
        afterHisId,
        promise: fetchPage(afterHisId).catch(() => null),
      };
    },
    [fetchPage]
  );

  // โหลดชุดแรกสุดใหม่ทั้งหมด (ใช้ตอนเปิดแท็บ/สลับอุปกรณ์/กดปุ่ม Reload)
  const loadFirstPage = useCallback(async () => {
    setLoading(true);
    setError("");
    prefetchRef.current = null;
    try {
      const page = await fetchPage(null);
      if (cancelledRef.current) return;
      dispatch({ type: "set_page", index: 0, page });
      prefetchNext(page);
    } catch (err) {
      if (!cancelledRef.current) setError(err.detail || "Failed to load command history");
    } finally {
      if (!cancelledRef.current) setLoading(false);
    }
  }, [fetchPage, prefetchNext]);

  // ไปหน้าถัดไป: ถ้าเคยโหลด/prefetch ไว้แล้วใช้เลยไม่ต้องรอ ถ้ายังไม่มีค่อย fetch สด ๆ
  async function goNext() {
    const nextIndex = nav.index + 1;
    if (nextIndex < nav.stack.length) {
      dispatch({ type: "go_to_index", index: nextIndex });
      return;
    }
    if (!currentPage || !currentPage.hasNext || currentPage.items.length === 0) return;
    const afterHisId = currentPage.items[currentPage.items.length - 1].his_id;

    let page = null;
    if (prefetchRef.current && prefetchRef.current.afterHisId === afterHisId) {
      page = await prefetchRef.current.promise;
    }
    if (!page) {
      setLoading(true);
      try {
        page = await fetchPage(afterHisId);
      } catch (err) {
        if (!cancelledRef.current) setError(err.detail || "Failed to load command history");
        setLoading(false);
        return;
      }
      setLoading(false);
    }
    if (cancelledRef.current) return;
    dispatch({ type: "set_page", index: nextIndex, page });
    prefetchRef.current = null;
    prefetchNext(page); // เตรียมชุดถัดไปต่ออีกทอดทันที
  }

  // ย้อนกลับหน้าก่อนหน้า: อยู่ใน stack อยู่แล้วเสมอ ไม่ต้อง fetch เลย
  function goPrev() {
    if (nav.index === 0) return;
    dispatch({ type: "go_to_index", index: nav.index - 1 });
  }

  useEffect(() => {
    cancelledRef.current = false;
    prefetchRef.current = null;
    dispatch({ type: "reset" }); // สลับอุปกรณ์ -> ล้าง cache หน้าเก่าทิ้ง กลับไปชุดแรก
    if (devId) loadFirstPage();
    return () => {
      cancelledRef.current = true;
    };
  }, [devId, loadFirstPage]);

  if (loading && !data) {
    return <div className="center-loading">Fetching command history...</div>;
  }
  if (error) {
    return <DismissibleError message={error} onDismiss={() => setError("")} />;
  }
  if (!data) {
    return null;
  }

  const groups = groupHistoryRows(data);
  // ลำดับที่ (No) ต้องนับต่อจากหน้าก่อนหน้า ไม่ใช่เริ่มที่ 1 ใหม่ทุกหน้า
  const rowOffset = nav.index * HISTORY_PAGE_SIZE;

  return (
    <div className="command-output">
      <div className="command-output-title" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem" }}>
        <h3 style={{ margin: 0, fontSize: "1.1rem", fontWeight: 600 }}>
          Command History
        </h3>
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <Reload_Result loading={loading} onRefresh={loadFirstPage} />
        </div>
      </div>
      <div style={{margin: "1rem 0"}}>
        <Pagination
          hasPrev={nav.index > 0}
          hasNext={!loading && !!currentPage?.hasNext}
          onPrev={goPrev}
          onNext={goNext}
        />
      </div>
      {data.length === 0 ? (
        <div className="config-placeholder">
          {nav.index > 0
            ? 'No more history on this page. Click "←" to go back.'
            : "No command history on this device yet"}
        </div>
      ) : (
        <table className="data-table">
          <thead>
            <tr>
              <th style={{ width: "5%" }}>No</th>
              <th style={{ width: "17%" }}>Time</th>
              <th style={{ width: "15%" }}>User</th>
              <th style={{ width: "20%" }}>Action</th>
              <th style={{ width: "43%" }}>Detail</th>
            </tr>
          </thead>
          <tbody>
            {groups.map((combo, index) => {
              const latest = combo[combo.length - 1];
              return (
                <tr key={combo.map((r) => r.his_id).join("-") || index}>
                  <td>{rowOffset + index + 1}</td>
                  <td>
                    <div style={{ fontWeight: 500 }}>{formatDate(latest.his_action_time)}</div>
                    <div style={{ fontSize: "0.75rem", opacity: 0.7, marginTop: "2px" }}>
                      {latest.his_action_time ? new Date(latest.his_action_time).toLocaleString("en-US") : "-"}
                    </div>
                  </td>
                  <td>{latest.his_usr_name || "Unknown user"}</td>
                  <td>
                    <div className="history-action-stack">
                      {combo.map((r) => (
                        <span key={r.his_id} className="badge badge-active history-action-badge">
                          {r.his_action}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td>
                    <div className="history-detail-stack">
                      {combo.map((r) => (
                        <div key={r.his_id}>{renderActionDetail(r)}</div>
                      ))}
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
      <div style={{margin: "1rem 0"}}>
        <Pagination
          hasPrev={nav.index > 0}
          hasNext={!loading && !!currentPage?.hasNext}
          onPrev={goPrev}
          onNext={goNext}
        />
      </div>
    </div>
  );
}
