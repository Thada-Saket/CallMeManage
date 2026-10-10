import DismissibleError from "../../DismissibleError";
import { useState } from "react";
import getDeviceInformation from "../../../hooks/getDeviceInformation";
import { runDeviceCommand, runDeviceTransaction } from "../../../api/api_devices";
import { juniperRelayRemovalSteps } from "../../../utils/juniperInterfaceTransaction";
import { splitInterfaceName } from "../../../utils/interfaceName";
import DhcpFormModal from "./dhcpFormModal";
import DhcpRelayFormModal from "./dhcpRelayFormModal";
import DhcpLocalInterfaceForm from "./dhcpLocalInterfaceForm";
import { parseExcludedRanges, relevantExcludeStrings } from "../../../utils/dhcpRange";
import Edit_Result from "../../commandResult/edit_command_result";
import { readDhcpLease, formatLeaseHours } from "../../../utils/dhcpLease";
import { juniperPoolRanges, ciscoPoolRanges } from "../../../utils/dhcpPoolRanges";
import PageTabs from "../../common/PageTabs";
import { rowClickSelection, rowDoubleClick } from "../../../utils/rowDoubleClick";

const DHCP_BASE_TABS = [
  { id: "dhcp_pool", label: "DHCP Pool" },
  { id: "dhcp_relay", label: "DHCP Relay" },
];

const DHCP_JUNIPER_TABS = [
  ...DHCP_BASE_TABS,
  { id: "dhcp_allow_interface", label: "DHCP Allow Interface" },
];

function ensureArray(value) {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

// แยกชื่อ bound interface เต็มๆ (เช่น "ge-0/0/6.0" จาก dhcp-local-server group)
// ออกเป็น {interfaceType, interfaceId, unit} - splitInterfaceName เดิมแยกได้แค่
// type/id ดิบ (id ยังติด ".0" อยู่) ต้องตัด unit ท้ายสุดออกมาต่างหากเพื่อส่งให้
// set_dhcp_server_interface/remove_dhcp_server_interface (รับ unit เป็น int แยก)
function splitBoundInterfaceName(fullName) {
  const { interfaceType, interfaceId } = splitInterfaceName(fullName || "");
  const lastDot = interfaceId.lastIndexOf(".");
  if (lastDot === -1) return { interfaceType, interfaceId, unit: 0 };
  return {
    interfaceType,
    interfaceId: interfaceId.slice(0, lastDot),
    unit: Number(interfaceId.slice(lastDot + 1)) || 0,
  };
}

// Junos: access/address-assignment/pool (subsystem ใหม่ - ย้ายมาจาก
// system/services/dhcp/pool เดิมที่ห้ามอยู่ร่วมกับ DHCP client บนอุปกรณ์เดียวกัน
// เลย ดู comment ยาวใน juniper_junos.py's set_dhcp_pool) "name" เป็น key จริง
// ของ pool แล้ว (ต่างจาก subsystem เก่าที่ key คือ network CIDR ไม่ใช้ name param
// ที่ผู้ใช้ตั้งเลย) มี lease config จริงแล้วด้วย (maximum-lease-time หน่วยวินาที)
// - **ไม่แปะ bound interface เข้ากับ pool อีกต่อไป** (2026-07-29 - user ขอแยก
// การจัดการ dhcp-local-server group's interface list ออกไปเป็นตาราง/ฟอร์มของ
// ตัวเองต่างหาก เพราะ Junos ไม่มี mapping "pool ไหนผูกกับ interface ไหน" จริง
// อยู่แล้ว (เลือก pool อัตโนมัติจาก subnet match ตอน runtime) - การผูก/ปลด
// interface เข้า dhcp-local-server ทำอัตโนมัติผ่าน DHCP Server toggle ที่หน้า
// Interfaces แทน ไม่มี UI แยกในหน้านี้แล้ว (ดู parseJuniperDhcpServerInterfaces
// ด้านล่าง - เหลือไว้เป็น mutual-exclusion guard เท่านั้น)
function parseJuniperPools(result) {
  const config = result?.payload?.data?.configuration;
  const pools = config?.access?.["address-assignment"]?.pool;
  if (!pools) return [];

  return ensureArray(pools).map((pool) => {
    const inet = pool?.family?.inet || {};
    const attrs = inet?.["dhcp-attributes"] || {};
    const dnsList = ensureArray(attrs?.["name-server"]).map((s) => (typeof s === "string" ? s : s?.name || ""));
    return {
      name: pool?.name || "",
      poolConfig: pool,
      network: inet?.network || "",
      gateway: ensureArray(attrs?.router)[0]?.name || "",
      dns: dnsList.filter(Boolean).join(", "),
      ...readDhcpLease("juniper", attrs),
      ...juniperPoolRanges(inet),
    };
  });
}

// เดิมมีตาราง "DHCP Interfaces" แยกต่างหากในหน้านี้ให้ user เพิ่ม/ลบ interface
// เข้า/ออกจาก dhcp-local-server (group "CM-DHCP") เอง - **user ขอตัดตารางนั้นออก
// ไปแล้ว** (ให้หน้าตาเหมือน Cisco ที่ไม่มี concept นี้เลย) เพราะการผูก/ปลด
// interface นี้ถูกทำอัตโนมัติแล้วผ่าน DHCP Server toggle ที่หน้า Interfaces
// (InterfacesFormModal.jsx's dhcpAction.followUp/toggle-off cleanup) ไม่ต้องมี
// UI แยกให้จัดการเองอีก - ฟังก์ชันนี้ยังต้องอยู่ต่อเพราะ InterfacesFormModal.jsx
// import ไปใช้เป็น mutual-exclusion guard (เช็คว่า interface เปิด DHCP Server
// อยู่แล้วไหมก่อนจะยอมให้เปิด DHCP Relay - Junos ไม่ให้เปิดพร้อมกัน) - เฉพาะ
// group ชื่อ "CM-DHCP" เท่านั้น (ไม่รวม group อื่นที่อาจตั้งไว้นอกแอปนี้)
export function parseJuniperDhcpServerInterfaces(result) {
  const config = result?.payload?.data?.configuration;
  const groups = ensureArray(config?.system?.services?.["dhcp-local-server"]?.group);
  // Actual bindings, including groups configured outside the application.
  return [...new Set(groups.flatMap(group => ensureArray(group.interface).map(entry => entry?.name).filter(Boolean)))];
}

// แปลงผล get_dhcp_pool_information (normalize_generic = JSON mirror โครงสร้าง tag)
// เป็นรายการ pool - tag ตรงกับที่ query filter ถาม (native/ip/dhcp/pool) และ
// โครงสร้างแต่ละ pool ตรงกับที่ set_dhcp_pool สร้าง (id/default-router/dns-server/
// network/lease) เลยรู้รูปร่างแน่นอน อ่านแบบ optional-chaining กัน pool เดี่ยว
// (object) vs หลาย pool (array) - คืน null ถ้า parse ไม่ได้ (ยี่ห้ออื่น) -> โชว์ raw
export function parsePools(result) {
  if (result?.vendor === "juniper") {
    try {
      return parseJuniperPools(result);
    } catch {
      return null;
    }
  }
  try {
    const dhcp = result?.payload?.data?.native?.ip?.dhcp;
    if (!dhcp) return [];
    // excluded-address เป็น global (พี่น้องของ pool ใน <dhcp> ไม่ผูกกับ pool ไหน
    // โดยเฉพาะ - ตรงกับพฤติกรรมจริงของ Cisco) เลยต้องกรองเอาเฉพาะที่ตกในช่วง
    // network ของแต่ละ pool เองอีกที เพื่อคำนวณ "ช่วงที่แจกได้จริง" กลับมา
    const excludedRanges = parseExcludedRanges(dhcp["excluded-address"]);
    return ensureArray(dhcp.pool).map((pool) => {
      const network = pool?.network?.["primary-network"] || {};
      const dnsList = ensureArray(pool?.["dns-server"]?.["dns-server-list"]);
      return {
        name: pool?.id || "",
        poolConfig: pool,
        network: network.number ? `${network.number} ${network.mask || ""}`.trim() : "",
        gateway: pool?.["default-router"]?.["default-router-list"] || "",
        dns: dnsList.join(", "),
        ...readDhcpLease("cisco", pool?.lease),
        ...ciscoPoolRanges(network, excludedRanges),
        // exclude ตัวจริง (ไม่ใช่ usable range) - ใช้ตอน edit ต้องลบ excluded-
        // address เดิมทิ้งก่อนเสมอ (เป็น global ไม่ผูกกับ pool - remove_dhcp_pool
        // ต้องรู้ค่าแน่นอนถึงจะลบถูก)
        excludeRanges: network.number ? relevantExcludeStrings(network, excludedRanges) : [],
      };
    });
  } catch {
    return null;
  }
}

function toDisplayText(value) {
  return typeof value === "string" || typeof value === "number" ? String(value) : "";
}

// Cisco: get_switchport_information ตอนนี้ unify ผลมาจาก backend แล้ว
// (normalize_switchport_layer ใน response_normalizer.py) เป็น
// [{name, layer, mode, helpers, raw}] ตรงๆ ไม่ใช่ raw native/interface subtree
// แบบเดิม (เปลี่ยนตอนแก้บั๊ก Layer 2/3 Unknown - ดู HANDOFF.md) - helpers เป็น
// array ของ DHCP server IP ต่อ interface อยู่แล้ว ไม่ต้อง parse XML เองอีก
function parseCiscoDhcpRelay(switchportResult) {
  if (!Array.isArray(switchportResult)) return [];
  const rows = [];
  for (const row of switchportResult) {
    for (const server of ensureArray(row?.helpers)) {
      if (server) rows.push({ interface: row.name, server });
    }
  }
  return rows;
}

// Juniper: forwarding-options/dhcp-relay (server-group + group/interface) -
// ย้ายมาจาก forwarding-options/helpers/bootp/server เดิมที่เป็น global scope
// ทั้งอุปกรณ์ ไม่ผูกกับ interface เลย (ดู comment ยาวใน juniper_junos.py's
// set_dhcp_relay) ตอนนี้ผูก interface จริงได้แล้ว - set_dhcp_relay ตั้งชื่อ
// server-group/group จากชื่อ interface เอง (SG-<if>/RELAY-<if>) เลย join กัน
// ผ่าน group's active-server-group เพื่อหาว่า server-group ไหนคู่กับ interface
// ไหนบ้าง (1 group ผูกได้หลาย interface + server-group เดียวมีได้หลาย address
// ในทางทฤษฎี แต่แอปนี้สร้างแบบ 1-group-ต่อ-1-interface เสมอ - โค้ดนี้รองรับ
// กรณีทั่วไปไว้เผื่อ config ถูกแก้นอกแอปมา) - เจอบั๊กจริง (2026-07-29): เดิมถ้า
// server-group ของ interface ไหนไม่มี address เหลืออยู่เลย (ว่างเปล่า - เจอ
// edge case จริงบน "ge-0/0/1.0" ที่ SG-ge-0-0-1-0 ไม่มี address ค้างอยู่ -
// เกิดจากลบ address ตัวสุดท้ายออกไปแล้วไม่ได้ลบ group/server-group ตามไปด้วย)
// เดิมโค้ดจะไม่ push แถวออกมาเลยสักแถว ทำให้ relay leg แบบนี้ "หายไป" จากตาราง
// ทั้งที่ interface ยังผูกอยู่จริง (mutual exclusion กับ dhcp-local-server ยัง
// มีผลอยู่เหมือนเดิม) user เจอปัญหาจริงจากตรงนี้ (error "already configured"
// ทั้งที่ "ในอุปกรณ์ไม่เห็น") - แก้แล้วโดย push แถวเดียวด้วย server: "" ถ้า
// server-group ว่าง แทนที่จะข้ามไปเงียบๆ (ให้ตาราง/ฟอร์ม edit เห็น + จัดการได้)
function parseJuniperDhcpRelay(result) {
  const dhcpRelay = result?.payload?.data?.configuration?.["forwarding-options"]?.["dhcp-relay"];
  if (!dhcpRelay) return [];
  const serverGroupAddresses = {};
  for (const sg of ensureArray(dhcpRelay?.["server-group"]?.["server-group"])) {
    const addresses = ensureArray(sg?.address).map((a) => toDisplayText(a?.name)).filter(Boolean);
    if (sg?.name) serverGroupAddresses[sg.name] = addresses;
  }
  const rows = [];
  for (const g of ensureArray(dhcpRelay?.group)) {
    const sgName = g?.["active-server-group"]?.["active-server-group"];
    const addresses = serverGroupAddresses[sgName] || [];
    for (const iface of ensureArray(g?.interface)) {
      const ifaceName = toDisplayText(iface?.name);
      if (!ifaceName) continue;
      if (addresses.length === 0) {
        rows.push({ interface: ifaceName, server: "" });
      } else {
        for (const server of addresses) {
          rows.push({ interface: ifaceName, server });
        }
      }
    }
  }
  return rows;
}

// เช็คแค่ "interface นี้ผูกกับ dhcp-relay group อยู่ไหม" (ไม่สนใจ server IP) -
// ใช้กับ guard ที่ไม่ต้องรู้ server address (InterfacesFormModal.jsx's
// mutual-exclusion guard ตอนจะเปิด DHCP Server บน interface ที่เป็น relay leg
// อยู่แล้ว) - derive จาก parseJuniperDhcpRelay() ตรงๆ (ครอบคลุมเคส server-group
// ว่างแล้วตั้งแต่ต้นทาง ไม่ต้อง parse XML ซ้ำสองที่)
export function parseJuniperDhcpRelayInterfaces(result) {
  try {
    return [...new Set(parseJuniperDhcpRelay(result).map((row) => row.interface))];
  } catch {
    return [];
  }
}

export function parseDhcpRelay(poolResult, switchportResult) {
  if (poolResult?.vendor === "juniper") {
    try {
      return parseJuniperDhcpRelay(poolResult);
    } catch {
      return null;
    }
  }
  try {
    return parseCiscoDhcpRelay(switchportResult);
  } catch {
    return null;
  }
}

export default function Dhcp({ devId }) {
  const { data, loading, error, clearError, refetch } = getDeviceInformation(devId, "get_dhcp_pool_information");
  // Cisco เท่านั้นที่ต้องการ query แยก (helper-address อยู่ใน native/interface
  // ไม่ใช่ native/ip/dhcp) - Juniper ได้ relay data มาจาก get_dhcp_pool_information
  // เดียวกันแล้วอยู่แล้ว (extend filter ไปแล้ว) query นี้ไม่ถูกใช้สำหรับ Juniper
  const {
    data: switchportData,
    loading: switchportLoading,
    refetch: refetchSwitchport,
  } = getDeviceInformation(devId, "get_switchport_information");
  const [activeTab, setActiveTab] = useState("dhcp_pool");
  const [showForm, setShowForm] = useState(false);
  const [poolFormMode, setPoolFormMode] = useState("create");
  const [selectedPoolName, setSelectedPoolName] = useState(null);
  const [showDeletePoolConfirm, setShowDeletePoolConfirm] = useState(false);
  const [deletingPool, setDeletingPool] = useState(false);
  const [deletePoolError, setDeletePoolError] = useState("");

  const [showRelayForm, setShowRelayForm] = useState(false);
  const [relayFormMode, setRelayFormMode] = useState("create");
  const [selectedRelayKey, setSelectedRelayKey] = useState(null); // `${interface}::${server}`
  // Juniper DHCP data อาจ refresh ระหว่างที่ฟอร์มเปิดอยู่ ถ้า derive editTarget
  // จาก relayRows ทุก render แถวที่เลือกอาจหายชั่วคราวจน editTarget กลายเป็น
  // null และ DhcpRelayFormModal ลดตัวเองเป็น create เงียบๆ ต่างจาก Interface
  // Form ที่ยึด target ตอนกด Edit ไว้ จึง snapshot แถวจริงก่อนเปิดฟอร์ม
  const [relayEditTarget, setRelayEditTarget] = useState(null);
  const [showDeleteRelayConfirm, setShowDeleteRelayConfirm] = useState(false);
  const [deletingRelay, setDeletingRelay] = useState(false);
  const [deleteRelayError, setDeleteRelayError] = useState("");

  function handleTabChange(nextTab) {
    setShowDeletePoolConfirm(false);
    setShowDeleteRelayConfirm(false);
    setActiveTab(nextTab);
  }

  function handleSaved() {
    setShowForm(false);
    setSelectedPoolName(null);
    refetch();
    refetchSwitchport();
  }

  function handleRelaySaved() {
    setShowRelayForm(false);
    setRelayEditTarget(null);
    setSelectedRelayKey(null);
    refetch();
    refetchSwitchport();
  }

  function handleRefresh() {
    refetch();
    refetchSwitchport();
  }

  function handleNewPool() {
    setActiveTab("dhcp_pool");
    setPoolFormMode("create");
    setShowForm(true);
  }

  function handleEditPool() {
    if (!selectedPoolName) return;
    setActiveTab("dhcp_pool");
    setPoolFormMode("edit");
    setShowForm(true);
  }

  async function handleConfirmDeletePool(pool) {
    setDeletingPool(true);
    setDeletePoolError("");
    try {
      // ลบ exclude เดิมของ pool นี้ไปด้วยเสมอ (global บน Cisco - ดู comment ใน
      // dhcpFormModal.jsx's edit flow) ไม่งั้นลบ pool ทิ้งแล้ว exclude ยังค้างตลอดไป
      // - ไม่แตะ dhcp-local-server group interface binding อีกต่อไป (แยกเป็น
      // ตาราง "DHCP Interfaces" ต่างหากแล้ว ไม่มี mapping 1-pool-ต่อ-1-interface
      // ให้ cleanup ตามอยู่แล้ว)
      await runDeviceCommand(devId, "remove_dhcp_pool", {
        name: pool.name,
        network: pool.network,
        exclude: pool.excludeRanges,
      });
      setShowDeletePoolConfirm(false);
      setSelectedPoolName(null);
      handleRefresh();
    } catch (err) {
      setDeletePoolError(err.detail || "Failed to delete DHCP pool");
    } finally {
      setDeletingPool(false);
    }
  }

  function handleNewRelay() {
    setActiveTab("dhcp_relay");
    setRelayFormMode("create");
    setRelayEditTarget(null);
    setShowRelayForm(true);
  }

  function handleEditRelay() {
    if (!selectedRelay) return;
    setActiveTab("dhcp_relay");
    setRelayFormMode("edit");
    setRelayEditTarget({...selectedRelay});
    setShowRelayForm(true);
  }

  async function handleConfirmDeleteRelay(relay) {
    // Juniper: relay.interface เป็นชื่อเต็มพร้อม unit เสมอ (เช่น "ge-0/0/1.0" -
    // มาจาก dhcp-relay/group/interface จริง) ต้องแยก unit ออกมาต่างหากด้วย
    // splitBoundInterfaceName (คำสั่งถอด relay interface รับ unit แยก) - Cisco
    // ไม่มี unit concept เลย ใช้ splitInterfaceName ธรรมดาพอ
    const params =
      vendor === "juniper"
        ? (() => {
            const { interfaceType, interfaceId, unit } = splitBoundInterfaceName(relay.interface);
            return { interface_type: interfaceType, interface_id: interfaceId, unit };
          })()
        : (() => {
            const { interfaceType, interfaceId } = splitInterfaceName(relay.interface);
            return { interface_type: interfaceType, interface_id: interfaceId };
          })();
    setDeletingRelay(true);
    setDeleteRelayError("");
    try {
      if (vendor === "juniper") {
        const latest = await runDeviceCommand(devId, "get_dhcp_pool_information", {});
        const configuration = latest?.normalized ? latest.result?.payload?.data?.configuration : null;
        if (!configuration) throw new Error("Failed to read latest DHCP configuration; relay not deleted");
        const commands = juniperRelayRemovalSteps({configuration, binding: params});
        if (!commands.length) throw new Error("Relay interface not found in latest configuration; please reload");
        await runDeviceTransaction(devId, commands);
      } else {
        await runDeviceCommand(devId, "remove_dhcp_relay", {
          ...params,
          helper_ip: relay.server,
        });
      }
      setShowDeleteRelayConfirm(false);
      setSelectedRelayKey(null);
      handleRefresh();
    } catch (err) {
      setDeleteRelayError(err.detail || err.message || "Failed to delete DHCP relay");
    } finally {
      setDeletingRelay(false);
    }
  }

  // รอทั้ง 2 query ให้เสร็จก่อนโชว์อะไรเลย (ไม่ใช่แค่ query แรก) - กันตาราง DHCP
  // Relay โผล่ทีหลังตาราง Pool เพราะ query คนละอันคนละเวลา resolve
  if ((loading && !data) || (switchportLoading && !switchportData)) {
    return <div className="center-loading">Loading DHCP pool data...</div>;
  }

  const vendor = data?.normalized ? data.result?.vendor : null;
  const pools = data?.normalized ? parsePools(data.result) : null;
  const relayRows = data?.normalized
    ? parseDhcpRelay(data.result, switchportData?.normalized ? switchportData.result : null)
    : null;
  // ใช้ parseJuniperDhcpRelayInterfaces (ไม่ใช่ relayRows) กันเคส server-group
  // ว่างไม่มี address (ดู comment ยาวที่ฟังก์ชันนั้น) - relayRows พลาดเคสนี้ไป
  // เงียบๆ ทำให้ dropdown ของฟอร์ม Add ยังโชว์ interface ที่เป็น relay leg อยู่จริง
  // ให้เลือกได้ แล้วโดนอุปกรณ์ปฏิเสธตอน submit
  const dhcpRelayInterfaces =
    vendor === "juniper" && data?.normalized ? parseJuniperDhcpRelayInterfaces(data.result) : [];
  const selectedPool = pools?.find((p) => p.name === selectedPoolName) || null;
  const selectedRelay = relayRows?.find((r) => `${r.interface}::${r.server}` === selectedRelayKey) || null;

  const tabs = vendor === "juniper" ? DHCP_JUNIPER_TABS : DHCP_BASE_TABS;
  const currentTab = tabs.some((t) => t.id === activeTab) ? activeTab : "dhcp_pool";

  return (
    <div className="command-configuration">
      {error && <DismissibleError message={error} onDismiss={clearError} />}

      {showForm ? (
        <DhcpFormModal
          devId={devId}
          vendor={vendor}
          mode={poolFormMode}
          editTarget={poolFormMode === "edit" ? selectedPool : null}
          onClose={() => setShowForm(false)}
          onSaved={handleSaved}
        />
      ) : showRelayForm ? (
        <DhcpRelayFormModal
          devId={devId}
          vendor={vendor}
          mode={relayFormMode}
          editTarget={relayFormMode === "edit" ? relayEditTarget : null}
          onClose={() => {
            setShowRelayForm(false);
            setRelayEditTarget(null);
          }}
          onSaved={handleRelaySaved}
        />
      ) : pools === null ? (
        data && (
          <pre>{typeof data.result === "string" ? data.result : JSON.stringify(data.result, null, 2)}</pre>
        )
      ) : (
        <>
          <PageTabs
            tabs={tabs}
            activeId={currentTab}
            onChange={handleTabChange}
            ariaLabel="DHCP Configuration Tabs"
          />

          {currentTab === "dhcp_pool" && (
            <div
              role="tabpanel"
              id="tabpanel-dhcp_pool"
              aria-labelledby="tab-dhcp_pool"
            >
              <div className="command-output-title">
                <Edit_Result
                  featureName="DHCP pool"
                  selectedLabel={selectedPool?.name || ""}
                  canEdit={!!selectedPoolName}
                  canDelete={!!selectedPoolName}
                  showDeleteConfirm={showDeletePoolConfirm}
                  deleting={deletingPool}
                  deleteError={deletePoolError} onDismissDeleteError={() => setDeletePoolError("")}
                  onNew={handleNewPool}
                  onEditClick={handleEditPool}
                  onOpenDeleteConfirm={() => setShowDeletePoolConfirm(true)}
                  onCancelDelete={() => setShowDeletePoolConfirm(false)}
                  onConfirmDelete={() => handleConfirmDeletePool(selectedPool)}
                  refreshing={loading || switchportLoading}
                  onRefresh={handleRefresh}
                />
              </div>

              {pools.length === 0 ? (
                <div className="config-placeholder">No DHCP pools configured</div>
              ) : (
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Pool Name</th>
                      <th>Network</th>
                      <th>Address Range</th>
                      <th>Gateway</th>
                      <th>DNS</th>
                      <th>Lease time (hours)</th>
                    </tr>
                  </thead>
                  <tbody>
                    {pools.map((pool, index) => (
                      <tr
                        key={`${pool.name}-${index}`}
                        className={`row-clickable ${pool.name === selectedPoolName ? "row-selected" : ""}`}
                        onClick={(event) => setSelectedPoolName(rowClickSelection(event, pool.name, selectedPoolName))}
                        onDoubleClick={rowDoubleClick(!!selectedPoolName, handleEditPool)}
                      >
                        <td>{pool.name || "-"}</td>
                        <td>{pool.network || "-"}</td>
                        <td>{pool.range || "-"}</td>
                        <td>{pool.gateway || "-"}</td>
                        <td>{pool.dns || "-"}</td>
                        <td>{formatLeaseHours(pool)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          )}

          {currentTab === "dhcp_relay" && (
            <div
              role="tabpanel"
              id="tabpanel-dhcp_relay"
              aria-labelledby="tab-dhcp_relay"
            >
              <div className="command-output-title">
                <Edit_Result
                  featureName="DHCP relay"
                  selectedLabel={selectedRelay ? `${selectedRelay.interface} -> ${selectedRelay.server || "(no server)"}` : ""}
                  canEdit={!!selectedRelay}
                  canDelete={!!selectedRelay}
                  showDeleteConfirm={showDeleteRelayConfirm}
                  deleting={deletingRelay}
                  deleteError={deleteRelayError} onDismissDeleteError={() => setDeleteRelayError("")}
                  onNew={handleNewRelay}
                  onEditClick={handleEditRelay}
                  onOpenDeleteConfirm={() => setShowDeleteRelayConfirm(true)}
                  onCancelDelete={() => setShowDeleteRelayConfirm(false)}
                  onConfirmDelete={() => handleConfirmDeleteRelay(selectedRelay)}
                  refreshing={loading || switchportLoading}
                  onRefresh={handleRefresh}
                />
              </div>

              {relayRows === null ? (
                switchportData && (
                  <pre>{typeof switchportData.result === "string" ? switchportData.result : JSON.stringify(switchportData.result, null, 2)}</pre>
                )
              ) : relayRows.length === 0 ? (
                <div className="config-placeholder">No DHCP Relay configured</div>
              ) : (
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Interface</th>
                      <th>DHCP Server IP</th>
                    </tr>
                  </thead>
                  <tbody>
                    {relayRows.map((row, index) => {
                      const key = `${row.interface}::${row.server}`;
                      return (
                        <tr
                          key={`${key}-${index}`}
                          className={`row-clickable ${key === selectedRelayKey ? "row-selected" : ""}`}
                          onClick={(event) => setSelectedRelayKey(rowClickSelection(event, key, selectedRelayKey))}
                          onDoubleClick={rowDoubleClick(!!selectedRelay, handleEditRelay)}
                        >
                          <td>{row.interface}</td>
                          <td>{row.server || "- (no server bound)"}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              )}
            </div>
          )}

          {vendor === "juniper" && (
            currentTab === "dhcp_allow_interface" ? (
              <div
                role="tabpanel"
                id="tabpanel-dhcp_allow_interface"
                aria-labelledby="tab-dhcp_allow_interface"
              >
                <div className="command-output-title">DHCP Allow Interface</div>
                <DhcpLocalInterfaceForm
                  devId={devId}
                  result={data.result}
                  relayInterfaces={dhcpRelayInterfaces}
                  loading={loading}
                  onRefresh={refetch}
                />
              </div>
            ) : null
          )}
        </>
      )}
    </div>
  );
}
