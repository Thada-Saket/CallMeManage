import DismissibleError from "../../DismissibleError";
import { useState } from "react";
import { runDeviceCommand, runDeviceTransaction } from "../../../api/api_devices";
import getDeviceInformation from "../../../hooks/getDeviceInformation";
import { useDeviceCapability } from "../../../hooks/deviceCapability";
import { parseSecurityTunnels } from "./parseSecurityTunnels";
import { parseJuniperOspf } from "../route/parseOspf";
// (bug 96) 2 ตัวนี้เคยเป็นของในไฟล์นี้เอง แต่ย้ายตามไปกับ parseSecurityTunnels.js
// ตอนแยกไฟล์ (bug 67) โดยที่โค้ดปลด zone membership ด้านล่างยังเรียกใช้อยู่
import { splitInterfaceName } from "../../../utils/interfaceName";
import { juniperOspfRemovalSteps, juniperProxyArpRemovalSteps } from "../../../utils/juniperInterfaceTransaction";

function ensureArray(value) {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}
import SecurityTunnelFormModal from "./security_tunnelFormModal";
import Edit_Result from "../../commandResult/edit_command_result";


// ชื่อ interface ทุกตัวที่ OSPF ของ Junos อ้างอยู่ (ทุก area รวมกัน) ใช้แสดงข้อมูล
// ก่อนยืนยันเท่านั้น ตอนลบจริงจะอ่าน running config สดและรวมการถอด reference ไว้ใน
// transaction เดียวกับการลบ tunnel ไม่อาศัยข้อมูลจาก hook ชุดนี้ตัดสินการเขียน
function ospfJuniperInterfaceNames(result) {
  try {
    const ospf = parseJuniperOspf(result?.payload?.data?.configuration?.protocols);
    return ospf.areas.flatMap((area) => area.interfaces.map((iface) => iface.name));
  } catch {
    return [];
  }
}

export default function SecurityTunnel({ devId, vendor }) {
  const isJuniper = vendor === "juniper";
  const { data, loading, error, clearError, refetch } = getDeviceInformation(devId, "get_security_tunnel_information");
  // (bug 94) ภาพสะท้อนของ bug 67 แต่คนละทิศ - bug 67 กันไม่ให้ลบ profile ที่มี tunnel
  // ผูกอยู่ · เคสนี้คือ tunnel ที่มี OSPF ผูกอยู่
  //
  // Cisco ปฏิเสธการลบ interface ที่ OSPF ยังอ้างชื่ออยู่ (`no passive-interface Tunnel0`
  // เป็น leafref ไปหา interface ตัวนั้นตรง ๆ) เดิมระบบยิงคำสั่งลบไปก่อนแล้วค่อยแปล
  // rpc-error กลับมาเป็นข้อความ - ผู้ใช้เห็นปุ่มลบกดได้ กดแล้วถึงรู้ว่าลบไม่ได้
  // ตอนนี้ฝั่ง Cisco เช็คตั้งแต่ก่อนกด: มีชื่อ tunnel อยู่ใน OSPF ไหม ถ้ามีก็ปิด
  // ปุ่มลบและให้ผู้ใช้แก้ routing เอง ส่วน Juniper ใช้ atomic cleanup ด้านล่าง
  //
  // **2 ยี่ห้อจัดการคนละแบบเพราะอุปกรณ์ทำคนละอย่าง**
  //   Cisco  - ปฏิเสธจริง จึงปิดปุ่มและให้ผู้ใช้แก้ routing ก่อนตามพฤติกรรมเดิม
  //   Junos  - ตอนยืนยันลบ ระบบอ่าน config สดและถอด OSPF reference พร้อมลบ tunnel
  //            ใน candidate transaction เดียว จึงไม่เหลือ interface กำพร้าใน OSPF
  //
  // เช็คแค่ OSPF ตัวเดียวเพราะ RIP ของ Cisco อ้าง network ไม่ได้อ้างชื่อ interface
  // จึงไม่มีทางบล็อกการลบด้วยชื่อ (เคส RIP ยังมีข้อความหลังยิงคำสั่งรับไว้เหมือนเดิม)
  const { data: ospfData, error: ospfError } = getDeviceInformation(devId, "get_ospf_information");
  // (dynamic feature) อุปกรณ์ที่ระบบตัดสินว่าทำ OSPF ไม่ได้จะไม่ถูกยิงคำสั่งนี้เลย - hook
  // คืน null ตลอด ซึ่งหน้าตาเหมือน "อ่านไม่สำเร็จ" เป๊ะ ๆ ต้องแยกให้ออก ไม่งั้นปุ่มลบจะถูก
  // ปิดถาวรบนอุปกรณ์ที่ไม่มี OSPF ให้ชนตั้งแต่แรก
  const { hiddenCommands } = useDeviceCapability();
  const ospfSkipped = hiddenCommands.has("get_ospf_information");
  const [formMode, setFormMode] = useState(null); // null | "create" | "edit"
  const [selectedName, setSelectedName] = useState(null);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState("");

  function handleSaved() {
    setFormMode(null);
    setSelectedName(null);
    refetch();
  }

  async function handleConfirmDelete(tunnel) {
    setDeleting(true);
    setDeleteError("");
    try {
      // Juniper: st0.N -> interface_number คือ N (unit number) / gr-0/0/0.0 ->
      // interface_number คือ "0/0/0" (slot - ตัด prefix "gr-" กับ ".0" unit
      // suffix ท้ายออก, unit fix เป็น "0" เสมอตามที่ create_security_tunnel สร้าง)
      const interfaceNumber = isJuniper
        ? tunnel.type === "GRE"
          ? tunnel.name.replace(/^gr-/, "").replace(/\.\d+$/, "")
          : tunnel.name.split(".").pop()
        : tunnel.name.replace(/^Tunnel/i, "");

      const removeTunnelParameters = isJuniper
        ? tunnel.type === "GRE"
          ? {
              interface_number: interfaceNumber,
              tunnel_type: "gre",
              ...(tunnel.real ? { gre_interface: tunnel.real.interfaceName, gre_unit: tunnel.real.unitName } : {}),
            }
          : {
              interface_number: interfaceNumber,
              tunnel_type: "ipsec",
              ipsec_profile: tunnel.securityProfile,
              ...(tunnel.real ? { vpn_name: tunnel.real.vpnName, bind_interface: tunnel.real.bindInterface } : {}),
            }
        : { interface_number: interfaceNumber };

      // Juniper: อ่าน running config ล่าสุด แล้วถอด Zone และ OSPF reference ของ
      // tunnel เป้าหมายพร้อมกับลบ tunnel ใน transaction เดียว Candidate จึง commit
      // ครั้งเดียว: สำเร็จครบหรือ rollback ครบ ไม่ทิ้ง config ครึ่งทาง
      if (isJuniper) {
        const latest = await runDeviceCommand(devId, "get_running_config", {});
        const configuration = latest?.normalized ? latest.result?.payload?.data?.configuration : null;
        if (!configuration?.interfaces) {
          throw new Error("Failed to read latest device configuration; Tunnel was not deleted");
        }
        const { interfaceType, interfaceId } = splitInterfaceName(tunnel.name);
        const commands = juniperProxyArpRemovalSteps({
          configuration,
          interfaceName: tunnel.name,
          interfaceType,
          interfaceId,
        });
        commands.push(...juniperOspfRemovalSteps({
          configuration,
          interfaceName: tunnel.name,
          interfaceType,
          interfaceId,
        }));
        for (const zone of ensureArray(configuration?.security?.zones?.["security-zone"])) {
          if (!ensureArray(zone?.interfaces).some((member) => member?.name === tunnel.name)) continue;
          if (!zone?.name) throw new Error("Incomplete Security Zone data; Tunnel was not deleted");
          commands.push({command: "remove_zone_member", parameters: {
            interface_type: interfaceType,
            interface_id: interfaceId,
            zone_name: zone.name,
          }});
        }
        commands.push({command: "remove_tunnel_interface", parameters: removeTunnelParameters});
        await runDeviceTransaction(devId, commands);
        setShowDeleteConfirm(false);
        setSelectedName(null);
        refetch();
        return;
      }

      const response = await runDeviceCommand(devId, "remove_tunnel_interface", removeTunnelParameters);
      // เจอบั๊กจริง (Cisco): remove_tunnel_interface ตอบกลับเป็น HTTP 200 พร้อม
      // {ok: false, errors: [...]} ตอนอุปกรณ์ปฏิเสธคำสั่งแบบ rpc-error (ไม่ใช่
      // exception) - runDeviceCommand เลย resolve ปกติ ไม่ throw - โค้ดเดิมไม่เคย
      // เช็ค ok เลย ปิด modal + refetch ราวกับสำเร็จทั้งที่ interface ไม่ได้ถูกลบ
      // จริง - ยืนยันจริงกับ HQ-R1/Tunnel0: ลบไม่ได้เพราะ OSPF ยังอ้างอิงอยู่
      // (no passive-interface Tunnel0 + network statement ครอบคลุมวง tunnel)
      const result = response?.result;
      if (result?.ok === false) {
        const errors = result.errors || [];
        const blockedByRouting = errors.some((e) =>
          /router-ospf|ios-ospf|router-rip|ios-rip/i.test(`${e.path || ""} ${e.bad_element || ""} ${e.message || ""}`)
        );
        setDeleteError(
          blockedByRouting
            ? "Cannot delete - This Tunnel is still referenced in OSPF/RIP (network statement or no passive-interface). Remove or edit reference in OSPF Routes or RIP Routes first, then delete this Tunnel again"
            : errors[0]?.message || "Failed to delete Tunnel"
        );
        return;
      }
      setShowDeleteConfirm(false);
      setSelectedName(null);
      refetch();
    } catch (err) {
      setDeleteError(err.detail || "Failed to delete Tunnel");
    } finally {
      setDeleting(false);
    }
  }

  if (loading && !data) return <div className="center-loading">Fetching Security Tunnel information...</div>;

  const tunnels = data?.normalized ? parseSecurityTunnels(data.result) : null;
  const selectedTunnel = tunnels?.find((tunnel) => tunnel.name === selectedName) || null;

  // (bug 94) Cisco: active_interfaces = interface ที่อยู่ใน passive-interface
  // disable-interface list นั่นคือ `no passive-interface <ชื่อ>` = OSPF อ้างชื่อนี้อยู่จริง
  // (bug 91) Juniper: ชื่อ interface อยู่ใต้ area โดยตรง อ่านด้วย parser ตัวเดียวกับหน้า OSPF
  const ospfInterfaces = new Set(
    isJuniper
      ? ospfJuniperInterfaceNames(ospfData?.result)
      : ensureArray(ospfData?.result?.active_interfaces)
  );
  const ospfHoldsTunnel = !!selectedTunnel && ospfInterfaces.has(selectedTunnel.name);
  // **"ยังไม่รู้" ต้องไม่ถูกนับเป็น "OSPF ไม่ได้อ้างอยู่"** (เคสเดียวกับด่าน tunnel ของหน้า
  // Security Profile) - ถ้าอ่านข้อมูล OSPF ไม่สำเร็จ/ยังไม่เสร็จ Set จะว่างเปล่าซึ่งหน้าตา
  // เหมือนกรณี "ไม่มี OSPF อ้างอยู่เลย" ทุกประการ เดิมจึงปลดล็อกปุ่มลบและกลืนคำเตือนทิ้ง
  // ในจังหวะที่อันตรายที่สุด: ฝั่ง Junos อุปกรณ์ยอมให้ลบจริง แล้วเหลือ `interface st0.x`
  // ค้างใน OSPF ชี้ไปที่ของที่ไม่มีอยู่ (bug 91 ข้อ 2 - ต้นเหตุที่ OSPF บน st0.0 ค้างที่
  // Address 0.0.0.0 ตอนไล่ปัญหา VPN) โดยผู้ใช้ไม่เคยเห็นคำเตือนเลย
  const ospfUnknown = !ospfSkipped && !ospfData?.normalized;
  // Tunnel ที่ตั้งจาก CLI ใช้ชื่อจริงใน `selectedTunnel.real` ทั้งตอนแก้และลบ จึงไม่ต้อง
  // ปิดปุ่มด้วย naming convention อีกต่อไป; managed เหลือเป็น metadata บอกที่มาเท่านั้น
  // Cisco ยังปิดปุ่มเมื่อ OSPF อ้างอยู่ ส่วน Juniper เก็บกวาด reference ให้อัตโนมัติ
  const ospfBlocksDelete = (ospfHoldsTunnel || ospfUnknown) && !isJuniper;
  const ospfBlockMessage = ospfUnknown
    ? isJuniper
      ? ""
      : `Unable to check if OSPF references Tunnel${ospfError ? ` (${ospfError})` : ""} - Delete is disabled until OSPF data is retrieved (click refresh and try again)`
    : !ospfHoldsTunnel
      ? ""
      : isJuniper
        ? `OSPF references ${selectedTunnel.name} - this reference will be removed automatically in the same transaction when the Tunnel is deleted`
        : `OSPF still references ${selectedTunnel.name} (no passive-interface) - Must remove this interface from OSPF in OSPF Routes page before deleting Tunnel`;

  return (
    <div className="command-configuration">
      {error && <DismissibleError message={error} onDismiss={clearError} />}

      {/* extraWarning ของ Edit_Result โผล่เฉพาะในกล่องยืนยันลบ ซึ่งเปิดไม่ได้เลยตอนปุ่มถูกปิด
          เหตุผลจึงต้องขึ้นบนหน้าด้วย ไม่งั้นผู้ใช้เจอปุ่มกดไม่ได้โดยไม่รู้ว่าต้องทำอะไรต่อ
          (ขึ้นเฉพาะตอนเลือกแถวอยู่ - ระหว่างโหลดไม่กี่ร้อย ms ไม่ต้องรบกวน) */}
      {ospfUnknown && selectedTunnel && ospfBlockMessage && <DismissibleError message={ospfBlockMessage} />}

      {/* allTunnels ส่ง tunnels ตรง ๆ (เป็น null ได้เมื่ออ่านตารางไม่สำเร็จ) - ฟอร์มต้องแยก
          "ยังไม่รู้" ออกจาก "ไม่มีเลย" ให้ได้ ไม่งั้นมันจะเลือกเลข Tunnel ถัดไปเป็น 0
          แล้วเขียนทับของจริง เพราะ create_security_tunnel ใช้ nc:operation="replace" */}
      {formMode ? (
        <SecurityTunnelFormModal
          devId={devId}
          vendor={vendor}
          mode={formMode}
          editTarget={formMode === "edit" ? selectedTunnel : null}
          allTunnels={tunnels}
          onClose={() => setFormMode(null)}
          onSaved={handleSaved}
        />
      ) : tunnels === null ? (
        data && (
          <pre>{typeof data.result === "string" ? data.result : JSON.stringify(data.result, null, 2)}</pre>
        )
      ) : (
        <>
          <div className="command-output-title">
            <Edit_Result
              featureName="Tunnel"
              selectedLabel={selectedTunnel ? `${selectedTunnel.name} (${selectedTunnel.type})` : ""}
              extraWarning={ospfBlockMessage || undefined}
              canEdit={!!selectedName}
              canDelete={!!selectedName && !ospfBlocksDelete}
              showDeleteConfirm={showDeleteConfirm}
              deleting={deleting}
              deleteError={deleteError} onDismissDeleteError={() => setDeleteError("")}
              onNew={() => setFormMode("create")}
              onEditClick={() => setFormMode("edit")}
              onOpenDeleteConfirm={() => setShowDeleteConfirm(true)}
              onCancelDelete={() => setShowDeleteConfirm(false)}
              onConfirmDelete={() => handleConfirmDelete(selectedTunnel)}
              refreshing={loading}
              onRefresh={refetch}
            />
          </div>

          {tunnels.length === 0 ? (
            <div className="config-placeholder">No Tunnel configured</div>
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Tunnel</th>
                  <th>Type</th>
                  <th>Tunnel IP</th>
                  <th>Source</th>
                  <th>Peer IP</th>
                  <th>Security Profile</th>
                </tr>
              </thead>
              <tbody>
                {tunnels.map((tunnel, index) => (
                  <tr
                    key={`${tunnel.name}-${index}`}
                    className={`row-clickable ${tunnel.name === selectedName ? "row-selected" : ""}`}
                    onClick={() => setSelectedName(tunnel.name === selectedName ? null : tunnel.name)}
                  >
                    <td>{tunnel.name}</td>
                    <td>{tunnel.type}</td>
                    <td>{tunnel.tunIp ? `${tunnel.tunIp} / ${tunnel.tunMask}` : "-"}</td>
                    <td>{tunnel.source || "-"}</td>
                    <td>{tunnel.destination || "-"}</td>
                    <td>{tunnel.securityProfile || "-"}</td>
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
