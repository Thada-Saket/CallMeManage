import DismissibleError from "../../DismissibleError";
import { useState } from "react";
import { runDeviceCommand, validateDeviceCommand } from "../../../api/api_devices";
import getDeviceInformation from "../../../hooks/getDeviceInformation";
import { splitInterfaceName } from "../../../utils/interfaceName";
import { validateIPv4Input } from "../../../utils/ipv4Input";
import { layer3StaticRouteInterfaces } from "../../../utils/staticRouteInterfaces";
import IPv4Input from "../../common/IPv4Input";

// ฟอร์มสร้าง/แก้ไข static route - เขียนเองตรงๆ ไม่ใช้ DynamicCommandForm กลาง
// เพราะ "ปลายทาง" ของ route เลือกได้ 2 แบบ (Next Hop IP / Exit Interface) ต้อง
// โชว์ฟิลด์คนละชุด เหมือน pattern เดียวกับ InterfaceFormModal.jsx
const NEXT_HOP_TYPE = { IP: "ip", INTERFACE: "interface" };

// โหมด Edit: pre-fill จาก route row (จาก extractStaticRoutes ใน static_route.jsx)
// - Cisco แยกแยะ IP-next-hop กับ interface-next-hop จากว่า outgoing-interface
// ว่างไหม (ยืนยันจริงบน HQ-R1): route ที่ตั้งด้วย next_hop มี iface="" กับ
// nextHop=IP จริง, route ที่ตั้งด้วย interface มี iface=ชื่อ interface กับ
// nextHop="0.0.0.0" (placeholder ไม่ใช่ IP จริง) - ใช้ presence ของ iface ตัดสิน
// destination ใช้ IPv4Input โหมด CIDR และ next hop ใช้โหมด address เพื่อจำกัด
// การกรอกตั้งแต่หน้า form แล้ว validate ซ้ำก่อนส่งคำสั่งด้วย shared validator เดียวกัน
function buildInitialValues(mode, editTarget) {
  if (mode !== "edit" || !editTarget) {
    return { nextHopType: NEXT_HOP_TYPE.IP, values: { destination: "", nextHop: "", interfaceName: "", distance: "" } };
  }
  const isInterface = !!editTarget.iface;
  // ค่า normalized จาก XML ปกติเป็น string แต่บังคับเป็น string ที่ขอบเขตของ form
  // เสมอ เพื่อให้ controlled input และ trim ตอน submit ไม่ขึ้นกับชนิดจาก vendor
  const distance = editTarget.distance == null ? "" : String(editTarget.distance);
  return {
    nextHopType: isInterface ? NEXT_HOP_TYPE.INTERFACE : NEXT_HOP_TYPE.IP,
    values: {
      destination: editTarget.prefix || "",
      nextHop: isInterface ? "" : editTarget.nextHop || "",
      interfaceName: isInterface ? editTarget.iface : "",
      distance: distance && distance !== "1" ? distance : "",
    },
  };
}

export default function StaticRouteFormModal({ devId, vendor, mode = "create", editTarget = null, onClose, onSaved }) {
  const isEdit = mode === "edit" && !!editTarget;
  const isHuawei = vendor === "huawei";
  const initial = buildInitialValues(mode, editTarget);
  // Huawei ลบ/สร้าง static route ด้วย next_hop เสมอ จึงไม่ให้ state เก่าจาก
  // route แบบ exit-interface เปิดทางเลือกที่อุปกรณ์ไม่ใช้แล้ว.
  const [nextHopType, setNextHopType] = useState(isHuawei ? NEXT_HOP_TYPE.IP : initial.nextHopType);
  const [values, setValues] = useState(initial.values);
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  // Static route แบบ Exit Interface ใช้ได้เฉพาะ Layer 3 จึงอ่านข้อมูล layer จริง
  // แทน get_interface_list ที่มีเพียงชื่อและแยก L2/L3 ไม่ได้
  const { data: layerData, loading: layerLoading, error: layerError } = getDeviceInformation(
    devId,
    "get_switchport_information",
    // ไม่ดึง config ก้อนนี้จนกว่าผู้ใช้เลือก Exit Interface; Huawei ไม่มีตัวเลือกนี้
    { auto: !isHuawei && nextHopType === NEXT_HOP_TYPE.INTERFACE }
  );
  const interfaceOptions = layerData?.normalized
    ? layer3StaticRouteInterfaces(layerData.result, vendor)
    : [];
  const canPickInterface = !layerError && interfaceOptions.length > 0;

  function setField(name, value) {
    setValues((prev) => ({ ...prev, [name]: value }));
  }

  // ช่องนี้ไม่ใช้ type="number" เพราะ browser ยังยอมให้พิมพ์ e, +, - และจุดได้
  // เก็บเฉพาะจำนวนเต็มที่อยู่ในช่วงจริงตั้งแต่ตอนพิมพ์หรือ paste แทน
  function setDistance(rawValue) {
    if (rawValue === "") {
      setField("distance", "");
      return;
    }
    if (!/^[0-9]{1,3}$/.test(rawValue)) return;
    const distance = Number(rawValue);
    if (distance < 1 || distance > 255) return;
    setField("distance", rawValue);
  }

  async function handleSubmit(event) {
    event.preventDefault();
    setError("");

    const destination = validateIPv4Input(values.destination, { mode: "cidr" });
    if (!destination.valid) {
      setError(`Invalid Destination Prefix: ${destination.error}`);
      return;
    }

    let nextHop = null;
    if (nextHopType === NEXT_HOP_TYPE.IP) {
      nextHop = validateIPv4Input(values.nextHop, { mode: "address" });
      if (!nextHop.valid) {
        setError(`Invalid Next Hop IP: ${nextHop.error}`);
        return;
      }
    }

    const distanceText = String(values.distance ?? "").trim();
    if (distanceText) {
      const distance = Number(distanceText);
      if (!/^[0-9]+$/.test(distanceText) || distance < 1 || distance > 255) {
        setError("Administrative Distance must be an integer between 1 and 255");
        return;
      }
    }

    setSubmitting(true);
    try {
      const parameters = {
        prefix: destination.address,
        mask: destination.prefix,
        distance: distanceText ? Number(distanceText) : undefined,
      };
      if (nextHopType === NEXT_HOP_TYPE.IP) {
        parameters.next_hop = nextHop.address;
      } else {
        const { interfaceType, interfaceId } = splitInterfaceName(values.interfaceName);
        parameters.interface_type = interfaceType;
        parameters.interface_id = interfaceId;
      }
      // Edit ของทั้งสามยี่ห้อส่ง key เดิมไปพร้อมค่าใหม่ใน set_static_route เพียง
      // คำสั่งเดียว translator จะ replace หรือรวม delete+create ไว้ใน edit-config
      // เดียว เมื่อค่าใหม่ผิด candidate จะถูก discard หรือ running จะ rollback
      // จึงไม่มีช่วงที่ route เดิมหายเหมือน flow remove แล้วค่อย set แบบเดิม
      if (isEdit) {
        const [oldPrefix, oldMask] = (editTarget.prefix || "").split("/");
        if (!oldPrefix || oldMask === undefined) throw new Error("Destination Prefix of previous static route not found");
        parameters.replace_prefix = oldPrefix;
        parameters.replace_mask = Number(oldMask);
        if (isHuawei) {
          // VRP ใช้ next-hop เป็นส่วนหนึ่งของ key จึงต้องส่ง key นี้เพิ่มจากอีกสองยี่ห้อ
          if (!editTarget.nextHop) throw new Error("Next Hop of previous static route not found");
          parameters.replace_next_hop = editTarget.nextHop;
        }
      }

      await validateDeviceCommand(devId, "set_static_route", parameters);
      await runDeviceCommand(devId, "set_static_route", parameters);
      onSaved();
    } catch (err) {
      setError(err.detail || (isEdit ? "Failed to edit static route" : "Failed to configure static route"));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form className="interface-configuration-form" onSubmit={handleSubmit}>
      {isEdit && <div className="command-output-title">Edit: {editTarget.prefix}</div>}
      {error && <DismissibleError message={error} onDismiss={() => setError("")} />}

      <div className="interface-configuration-form-field">
        <label className="data-label">Destination Prefix (CIDR)</label>
        <IPv4Input
          id="static-route-destination"
          label="Destination Prefix"
          mode="cidr"
          value={values.destination}
          onChange={(value) => setField("destination", value)}
          required
        />
      </div>

      {/* Huawei รับ static route ผ่าน next_hop เท่านั้น จึงซ่อนตัวเลือกปลายทาง
          และ Exit Interface โดยไม่แตะฟอร์ม Cisco/Juniper ที่ยังใช้ได้อยู่ */}
      {!isHuawei && (
        <div className="interface-configuration-form-field">
          <label className="data-label">Next Hop Type</label>
          <div className="segmented-control">
            <input
              type="radio"
              id="static-route-nexthop-ip"
              name="static-route-nexthop-type"
              value={NEXT_HOP_TYPE.IP}
              checked={nextHopType === NEXT_HOP_TYPE.IP}
              onChange={(event) => setNextHopType(event.target.value)}
            />
            <label htmlFor="static-route-nexthop-ip">Next Hop IP</label>
            <input
              type="radio"
              id="static-route-nexthop-interface"
              name="static-route-nexthop-type"
              value={NEXT_HOP_TYPE.INTERFACE}
              checked={nextHopType === NEXT_HOP_TYPE.INTERFACE}
              onChange={(event) => setNextHopType(event.target.value)}
            />
            <label htmlFor="static-route-nexthop-interface">Exit Interface</label>
          </div>
        </div>
      )}

      {nextHopType === NEXT_HOP_TYPE.IP ? (
        <div className="interface-configuration-form-field">
          <label className="data-label">Next Hop IP</label>
          <IPv4Input
            id="static-route-next-hop"
            label="Next Hop IP"
            mode="address"
            value={values.nextHop}
            onChange={(value) => setField("nextHop", value)}
            required
          />
        </div>
      ) : (
        <div className="interface-configuration-form-field">
          <label className="data-label">Exit Interface</label>
          {layerLoading ? (
            <select disabled value="">
              <option value="">Loading Layer 3 interfaces...</option>
            </select>
          ) : canPickInterface ? (
            <select
              value={values.interfaceName}
              onChange={(event) => setField("interfaceName", event.target.value)}
              required
            >
              <option value="" disabled>-- Select interface --</option>
              {interfaceOptions.map((name) => (
                <option key={name} value={name}>
                  {name}
                </option>
              ))}
            </select>
          ) : (
            <select disabled value="">
              <option value="">
                {layerError ? "Failed to load interface Layer information" : "No Layer 3 interfaces found"}
              </option>
            </select>
          )}
          {!canPickInterface && !layerLoading && (
            <span className="field-hint">
              Static route with Exit Interface can only select Layer 3 interfaces.
            </span>
          )}
        </div>
      )}

      <div className="interface-configuration-form-field">
        <label className="data-label">Administrative Distance (optional)</label>
        <input
          type="text"
          inputMode="numeric"
          autoComplete="off"
          maxLength={3}
          placeholder="1"
          value={values.distance}
          onChange={(event) => setDistance(event.target.value)}
          aria-label="Administrative Distance 1 to 255"
        />
      </div>

      <div className="interface-form-btn-container">
        <button type="submit" className="btn btn-primary" disabled={submitting}>
          {submitting ? "Sending..." : isEdit ? "Save" : "OK"}
        </button>
        <button type="button" className="btn btn-ghost" onClick={onClose}>
          Cancel
        </button>
      </div>
    </form>
  );
}
