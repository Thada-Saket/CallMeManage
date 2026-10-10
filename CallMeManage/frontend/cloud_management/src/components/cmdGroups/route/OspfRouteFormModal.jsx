import DismissibleError from "../../DismissibleError";
import { useState } from "react";
import { runDeviceCommand, validateDeviceCommand } from "../../../api/api_devices";
import getDeviceInformation from "../../../hooks/getDeviceInformation";
import { normalizeIP } from "../../../utils/normalizeIP";
import { normalizeSubnet } from "../../../utils/normalizeSubnet";
import { buildRoutingPickerOptions, networkAddressOf, selectAnyRoutingNetworks } from "../../../utils/routingNetworkOptions";
import IPv4Input from "../../common/IPv4Input";
import { acceptsOspfAreaInput, acceptsOspfProcessIdInput, ospfAreaToNumber } from "../../../utils/ospfArea";
import CheckboxDropdown from "../../common/CheckboxDropdown";

// pre-fill จาก currentRule = ผลลัพธ์ get_ospf_information ตรงๆ (Cisco -
// process_id/router_id/networks[]/active_interfaces[]/passive_interface_default/
// default_information_originate/redistribute_static) - null = ยังไม่มี OSPF
// process เลย (ฟอร์มว่างเปล่า) scopeMode ล็อกเป็น "specific" เสมอถ้ามี process
// อยู่แล้วเพราะ networks ที่ตั้งไว้จริงอาจไม่ตรงกับที่ "any" mode จะคำนวณใหม่จาก
// interface ปัจจุบัน (เช่น interface เปลี่ยน IP ไปแล้วหลังตั้ง OSPF) - ต้องโชว์
// ค่าที่ "ตั้งไว้จริง" ไม่ใช่ค่าที่คำนวณใหม่
function buildInitialValuesCisco(currentRule) {
  if (!currentRule) {
    return {
      processId: "",
      routerId: "",
      scopeMode: "any",
      networks: [],
      area: "",
      defaultInformationOriginate: false,
      redistributeStatic: false,
      redistributeRip: false,
      passiveInterfaceDefault: false,
      noPassiveInterfaces: [],
    };
  }
  // networks เก็บ**ชื่อ interface**ที่เลือกไว้ตรงๆ ตอนนี้ (ดู 5.1 - เปลี่ยนจาก
  // กรอก CIDR ข้อความเป็นเลือก interface เหมือน Juniper) - ตอน edit ต้อง
  // reverse-match network address กลับเป็นชื่อ interface ซึ่งต้องรอ
  // interfaceRows โหลดเสร็จก่อน (ยังไม่มีตอนนี้ที่ useState initializer นี้ทำงาน)
  // เว้นว่างไว้ก่อนแล้วให้ useEffect ด้านล่างเติมให้ทีหลังเมื่อข้อมูลพร้อม
  return {
    processId: currentRule.process_id != null ? String(currentRule.process_id) : "",
    routerId: currentRule.router_id || "",
    scopeMode: "specific",
    // เก็บ network address ที่ตั้งไว้จริงบนอุปกรณ์ตรง ๆ - ตรงกับ value ของ
    // ตัวเลือกใน picker (RIP ใช้สัญญาเดียวกัน) จึงไม่ต้อง reverse-match กลับเป็น
    // ชื่อ interface ทีหลังอีกแล้ว
    networks: (currentRule.networks || []).map((entry) => entry.network).filter(Boolean),
    area: ospfAreaToNumber(currentRule.networks?.[0]?.area),
    defaultInformationOriginate: !!currentRule.default_information_originate,
    redistributeStatic: !!currentRule.redistribute_static,
    redistributeRip: !!currentRule.redistribute_rip,
    passiveInterfaceDefault: !!currentRule.passive_interface_default,
    noPassiveInterfaces: currentRule.active_interfaces || [],
  };
}

// Juniper: currentRule = parseJuniperOspf() ผลลัพธ์ ({areas: [{name,
// interfaces: [{name, passive}]}], defaultInformationOriginate,
// redistributeStatic, redistributeRip, routerId}) - รูปร่างต่างจาก Cisco สิ้นเชิง
// (ไม่มี process_id และ router-id อยู่ routing-options/router-id คนละ subtree -
// parseJuniperOspf รับค่าที่ get_ospf_information query มาด้วยแล้วตาม bug 86) -
// ตัด area/interfaces จาก area แรกมาแสดง (เหมือนที่ Cisco
// ฝั่งนี้ก็ simplify เป็น area เดียวต่อฟอร์มอยู่แล้ว ไม่ใช่ regression ใหม่)
// "Passive Interface Default" เป็น software-defined UI concept ล้วนๆ (Junos
// เองไม่มี "default" - mark passive ทีละ interface ตรงๆ เท่านั้น ดู
// set_ospf_passive_interface) - mirror UI/state เดียวกับที่ Cisco มีอยู่แล้ว
// (passiveInterfaceDefault + noPassiveInterfaces exception list) แทนที่ toggle
// per-interface แบบเดิม (passiveInterfaces - opt-in ทีละตัว ค่าเริ่มต้นคือ
// active ทั้งหมด) ตามที่สเปกข้อ 5.2 ขอ (ค่าเริ่มต้น = passive ทั้งหมด ผู้ใช้ค่อย
// เลือก "ปลด Passive" เฉพาะตัวที่ต้องการ)
function buildInitialValuesJuniper(currentRule) {
  if (!currentRule) {
    return {
      routerId: "",
      area: "",
      scopeMode: "any",
      interfaces: [],
      passiveInterfaceDefault: false,
      noPassiveInterfaces: [],
      defaultInformationOriginate: false,
      redistributeStatic: false,
      redistributeRip: false,
    };
  }
  const firstArea = currentRule.areas?.[0];
  const interfaceEntries = firstArea?.interfaces || [];
  const interfaceNames = interfaceEntries.map((i) => i.name).filter(Boolean);
  // เดาสถานะ "Passive Interface Default" จากข้อมูลจริงตอน edit: ถ้ามี interface
  // ไหน passive อยู่แล้วอย่างน้อย 1 ตัว ถือว่าโหมดนี้เปิดอยู่ (ไม่มี flag เดี่ยว
  // เก็บบนอุปกรณ์จริงให้ query ตรงๆ - เป็นแค่ UI state ฝั่งเราเอง)
  const passiveInterfaceDefault = interfaceEntries.some((i) => i.passive);
  const noPassiveInterfaces = interfaceEntries.filter((i) => !i.passive).map((i) => i.name);
  return {
    routerId: currentRule.routerId || "",
    // Junos คืน area เป็น dotted quad เสมอ ("0.0.0.3") ช่องกรอกเป็นเลขล้วน
    area: ospfAreaToNumber(firstArea?.name),
    scopeMode: "specific",
    interfaces: interfaceNames,
    passiveInterfaceDefault,
    noPassiveInterfaces,
    defaultInformationOriginate: !!currentRule.defaultInformationOriginate,
    redistributeStatic: !!currentRule.redistributeStatic,
    redistributeRip: !!currentRule.redistributeRip,
  };
}

// เพิ่ม OSPF network เข้า process ที่มีอยู่ (หรือสร้างใหม่) - ต่างจาก RIP ตรงที่
// set_ospf_network รับทีละ network+wildcard (Cisco) หรือทีละ interface
// (Juniper) 1 ตัว ไม่ใช่ list เดียวจบแบบ RIP เลยต้องยิงหลายคำสั่งถ้ามีมากกว่า 1
// รายการ (เหมือน DHCP-on-interface ที่ bundle หลาย backend call ไว้ใน submit
// เดียว)
//
// **Juniper ไม่มี concept ต่อไปนี้เลย** ต่างจาก Cisco โดยพื้นฐาน:
// - Process ID: instance เดียวต่อ routing-instance เสมอ ไม่มี process-id
// - network+wildcard: ผูก OSPF ต่อ**interface**ตรงๆ ไม่ใช่ network+wildcard
// - "Passive Interface Default + No Passive exceptions": Junos ทำเครื่องหมาย
//   passive ทีละ interface ตรงๆ (set_ospf_passive_interface) ไม่มี "default"
//   ที่ประกาศทุก interface passive แล้วยกเว้นทีหลัง
// - default_information_originate เป็น flag เดียว: set_ospf_default_originate()
//   ไม่รับ param เลย (ไม่ผูกกับ process_id/value)
//
// currentRule มาจาก toggle "Enable OSPF" เดียวกันทั้ง 2 ยี่ห้อแล้ว (เดิม Juniper
// ใช้ formMode/editTarget+onClose แยกเป็น New/Edit/Delete ต่างหาก - รวม UI เป็น
// อันเดียวกับ Cisco ตามที่ user ขอ - ไม่มีปุ่ม Cancel เพราะปิดฟอร์มด้วย toggle)
export default function OspfRouteFormModal({ devId, vendor, currentRule = null, onSaved }) {
  const isJuniper = vendor === "juniper";
  const isEdit = !!currentRule;
  const [values, setValues] = useState(
    isJuniper ? buildInitialValuesJuniper(currentRule) : buildInitialValuesCisco(currentRule)
  );
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const { data: ifData, loading: ifLoading } = getDeviceInformation(devId, "get_ip_interface_brief");
  const interfaceRows = ifData?.normalized ? ifData.result : [];

  function setField(name, value) {
    setValues((prev) => ({ ...prev, [name]: value }));
  }

  // ช่องเลือกเป็น dropdown ติ๊กช่องตัวเดียวแบบเดียวกับฟอร์ม RIP แล้ว (เลิกใช้
  // โมเดลเพิ่มทีละแถวด้วยปุ่ม +/-) - Juniper เก็บ "ชื่อขา" ส่วน Cisco เก็บ
  // "network address" ของ IP ที่ติ๊ก ตรงกับ value ของตัวเลือกใน picker
  const selectionKey = isJuniper ? "interfaces" : "networks";
  const selected = (values[selectionKey] || []).filter(Boolean);
  const pickerOptions = buildRoutingPickerOptions({ interfaceRows, selected, isJuniper });

  function toggleSelection(value) {
    setField(
      selectionKey,
      selected.includes(value) ? selected.filter((entry) => entry !== value) : [...selected, value]
    );
  }

  function toggleNoPassive(interfaceName) {
    setValues((prev) => {
      const exists = prev.noPassiveInterfaces.includes(interfaceName);
      return {
        ...prev,
        noPassiveInterfaces: exists
          ? prev.noPassiveInterfaces.filter((name) => name !== interfaceName)
          : [...prev.noPassiveInterfaces, interfaceName],
      };
    });
  }

  // แถวที่จะประกาศเข้า OSPF จริงรอบนี้ - ใช้ทั้งตอน render ตาราง "No Passive"
  // และตอน submit (คำนวณที่เดียว ไม่ให้สองที่เพี้ยนออกจากกัน) - คืน network,
  // wildcard และชื่อ interface ที่ผูกกับ network นั้น
  //
  // Cisco: ค่าที่ติ๊ก/ที่โหมด Any เลือกให้ เป็น network address ต้องย้อนกลับไปหา
  // แถว interface เพื่อเอา wildcard กับชื่อขา · network ที่ตั้งไว้บนอุปกรณ์แล้ว
  // แต่หาแถวที่ตรงไม่เจอ (เช่น IOS ย่อ network เป็น classful หรือขาถูกลบไปแล้ว)
  // ต้องคงไว้ด้วย wildcard เดิมจาก currentRule ไม่ใช่ปล่อยหายเงียบ ๆ ตอน Apply
  function getAnnouncedRows() {
    const wanted = values.scopeMode === "any"
      ? selectAnyRoutingNetworks({ interfaceRows, isJuniper })
      : selected;
    if (isJuniper) return wanted.map((interfaceName) => ({ interfaceName }));

    const configuredWildcards = new Map(
      (currentRule?.networks || []).filter((entry) => entry.network).map((entry) => [entry.network, entry.wildcard])
    );
    const rows = [];
    for (const network of wanted) {
      const match = interfaceRows.find((row) => {
        const ip = normalizeIP(row.ip);
        const subnet = normalizeSubnet(row.subnet);
        return ip && ip !== "-" && subnet && networkAddressOf(ip, subnet.prefix) === network;
      });
      if (match) {
        rows.push({
          network,
          wildcard: normalizeSubnet(match.subnet).wildcardMask,
          interfaceName: match.name,
        });
        continue;
      }
      const wildcard = configuredWildcards.get(network);
      if (wildcard) rows.push({ network, wildcard, interfaceName: "" });
    }
    return rows;
  }

  async function handleSubmitJuniper(event) {
    event.preventDefault();
    setError("");

    const area = values.area.trim();
    if (area === "") return setError("Please enter Area as a number between 0 and 4294967295");
    const interfaces = getAnnouncedRows().map((row) => row.interfaceName).filter(Boolean);
    if (interfaces.length === 0) {
      return setError(values.scopeMode === "any"
        ? "No internal (private) interfaces found - try selecting Specific instead"
        : "Select at least one interface");
    }

    setSubmitting(true);
    try {
      // แก้ไข process ที่มีอยู่แล้วต้องลบของเดิมทิ้งทั้งก้อนก่อนเสมอ (ไม่ใช่แค่เรียก
      // set_ospf_network ซ้ำ) เพราะ area/interface list merge แบบ "เพิ่ม" ไม่ใช่
      // แทนที่ (pattern เดียวกับ RIP/static route/DHCP pool ที่ผ่านมา)
      // (ระลอก C2) เดิมยิงได้ถึง 12 RPC: remove_ospf_routing แล้ววน set_ospf_network +
      // set_ospf_passive_interface ทีละ interface - และเพราะ Junos commit ทุก
      // edit-config จึงกลายเป็น 12 commit ด้วย มีช่วงที่ routing หายไปกลางทางจริง
      //
      // ตอนนี้ replace_ospf_area ตั้งทั้ง area ใน edit-config เดียว (nc:operation=
      // "replace") + commit ครั้งเดียว = atomic จริงจาก candidate ของ Junos
      // **1 action = 1 RPC = ประวัติ 1 แถว** และไม่ต้องลบอะไรก่อนเลย
      const routerId = values.routerId.trim() || undefined;
      const passiveList = values.passiveInterfaceDefault
        ? interfaces.filter((name) => !values.noPassiveInterfaces.includes(name))
        : [];
      const ospfParams = {
        area: Number(area),
        interfaces,
        passive_interfaces: passiveList,
        router_id: routerId,
        // เดิมไม่ได้ส่ง 3 ค่านี้เลย - toggle ไม่มีผล และ replace ที่ระดับ <ospf> ลบ
        // export ที่ตั้งไว้เดิมทิ้งทุกครั้งที่ Apply (ดู replace_ospf_area)
        default_originate: values.defaultInformationOriginate,
        redistribute_static: values.redistributeStatic,
        redistribute_rip: values.redistributeRip,
      };
      await validateDeviceCommand(devId, "replace_ospf_area", ospfParams);
      await runDeviceCommand(devId, "replace_ospf_area", ospfParams);
      onSaved();
    } catch (err) {
      setError(err.detail || (isEdit ? "Failed to edit OSPF" : "Failed to configure OSPF"));
    } finally {
      setSubmitting(false);
    }
  }

  async function handleSubmitCisco(event) {
    event.preventDefault();
    setError("");

    // ตอน edit ใช้ process_id เดิมจากอุปกรณ์เสมอ - replace ทำงานแค่ใต้ <process-id>
    // ที่ส่งไป ถ้าส่ง id ใหม่ process เดิมจะค้างอยู่คู่กันเป็น 2 process (ช่องนี้ล็อก
    // ไว้ตอน edit แล้ว แต่ไม่พึ่ง UI อย่างเดียว)
    const processId = isEdit ? String(currentRule.process_id) : values.processId.trim();
    const routerId = values.routerId.trim();
    const area = values.area.trim();
    if (!processId) return setError("Please enter Process ID");
    if (area === "") return setError("Please enter Area as a number between 0 and 4294967295");

    // (bug 72) เก็บชื่อ interface ที่อยู่ใน OSPF จริงรอบนี้ไว้ด้วย - ใช้กรอง
    // noPassiveInterfaces ตอนท้าย ไม่งั้นขาที่ผู้ใช้เอาออกจาก OSPF ไปแล้วจะยังถูกส่ง
    // no_passive กลับไปให้อุปกรณ์ ทำให้บรรทัด "no passive-interface X" ค้างอยู่
    const announced = getAnnouncedRows();
    if (announced.length === 0) {
      setError(values.scopeMode === "any"
        ? "No internal (private) networks found from interfaces - try selecting Specific instead"
        : "Select at least one IP address");
      return;
    }
    const networks = announced.map(({ network, wildcard }) => ({ network, wildcard }));
    const ospfInterfaceNames = announced.map((row) => row.interfaceName).filter(Boolean);

    setSubmitting(true);
    try {
      // แก้ไข process ที่มีอยู่แล้วต้องลบของเดิมทิ้งทั้งก้อนก่อนเสมอ (ไม่ใช่แค่เรียก
      // set_ospf_network ซ้ำ) เพราะ network/passive-interface list merge แบบ "เพิ่ม"
      // ไม่ใช่แทนที่ (pattern เดียวกับ static route/DHCP pool ที่ผ่านมา) - ใช้
      // process_id เดิมจาก currentRule เสมอตอน edit (ดู processId ด้านบน)
      // (ระลอก C2) เดิมยิง remove_ospf_process แล้ววน set_ospf_network ทีละ network
      // + default_originate + redistribute อีก 2 + passive_interface รวมได้ถึง 12 RPC
      // ถ้าพังกลางทางจะได้ routing ครึ่ง ๆ กลาง ๆ (บาง network เข้าแล้ว บางตัวยัง)
      //
      // ทุกอย่างอยู่ใต้ <process-id> เดียวกัน จึงยุบเป็น nc:operation="replace" ก้อนเดียว
      // ได้ - ไม่ต้องลบก่อน เพราะ replace แทนที่เนื้อหาทั้งหมดใต้ process นั้นให้เอง
      // (เดิมต้องลบเพราะ list merge แบบ "เพิ่ม" ไม่ใช่แทนที่)
      const ospfParams = {
        process_id: Number(processId),
        networks: networks.map(({ network, wildcard }) => ({ network, wildcard, area: Number(area) })),
        router_id: routerId || undefined,
        default_originate: values.defaultInformationOriginate,
        redistribute_static: values.redistributeStatic,
        redistribute_rip: values.redistributeRip,
        passive_default: values.passiveInterfaceDefault,
        // (bug 72) ส่งเฉพาะขาที่ยังอยู่ใน OSPF รอบนี้ - ฝั่ง Juniper กรองแบบนี้อยู่แล้ว
        no_passive: values.passiveInterfaceDefault
          ? values.noPassiveInterfaces.filter((name) => ospfInterfaceNames.includes(name))
          : [],
      };
      await validateDeviceCommand(devId, "replace_ospf_process", ospfParams);
      await runDeviceCommand(devId, "replace_ospf_process", ospfParams);
      onSaved();
    } catch (err) {
      setError(err.detail || (isEdit ? "Failed to edit OSPF" : "Failed to configure OSPF"));
    } finally {
      setSubmitting(false);
    }
  }

  const handleSubmit = isJuniper ? handleSubmitJuniper : handleSubmitCisco;
  // ทั้งสองยี่ห้อใช้ชุดเดียวกันแล้ว - Juniper ได้ [{interfaceName}] ส่วน Cisco ได้
  // {network, wildcard, interfaceName} ครบ
  const announcedRows = getAnnouncedRows();

  return (
    <form onSubmit={handleSubmit}>
      {error && <DismissibleError message={error} onDismiss={() => setError("")} />}

      {/* Junos ไม่มี process-id concept เลย (instance เดียวต่อ routing-instance) -
          ซ่อนไปเลยสำหรับ Juniper */}
      {!isJuniper && (
        <div className="interface-configuration-form-field">
          <label className="data-label">Process ID</label>
          {/* 1-65535 ตาม schema จริงของอุปกรณ์ - ปฏิเสธคีย์ที่ทำให้ค่าออกนอกช่วง
              ตั้งแต่ตอนพิมพ์ ค่าเดิมจึงคงอยู่เสมอ (แนวเดียวกับช่อง Area)
              ใช้ type="text" ไม่ใช่ number เพราะ input number ปล่อยให้พิมพ์ e/+/-
              และค่าเกินช่วงลงไปได้ แล้วค่อยฟ้องทีหลัง */}
          <input
            type="text"
            inputMode="numeric"
            placeholder="1"
            value={values.processId}
            onChange={(event) => {
              if (acceptsOspfProcessIdInput(event.target.value)) setField("processId", event.target.value);
            }}
            readOnly={isEdit}
            required
          />
          {isEdit && (
            <div className="field-hint">Process ID cannot be changed - disable OSPF and re-enable to use a different ID</div>
          )}
        </div>
      )}

      {/* ใช้ IPv4Input ชุดเดียวกับ Next Hop IP ของ StaticRouteFormModal - ช่องละ
          octet กรอกได้เฉพาะ 0-255 และตรวจรูปแบบให้เองตอนออกจากช่อง (รองรับ
          0.0.0.x อยู่แล้ว ไม่ต้องทำ validator ใหม่)

          ข้อจำกัด martian ของ Juniper **ไม่แสดงตรงนี้** ตามที่กำหนด - ผู้ใช้กรอก
          อะไรก็ได้ตามปกติ แล้วค่อยรู้ตอนกด Apply ถ้าค่านั้นใช้ไม่ได้ (ข้อความมา
          จาก _validate_router_id ใน vendor_translators/juniper_junos.py ผ่าน
          validateDeviceCommand ซึ่งไม่แตะอุปกรณ์เลย) */}
      <div className="interface-configuration-form-field">
        <label className="data-label">Router ID (optional)</label>
        <IPv4Input
          id="ospf-router-id"
          label="Router ID"
          mode="address"
          value={values.routerId}
          onChange={(value) => setField("routerId", value)}
        />
      </div>

      {/* Area เป็นเลขล้วน 0-4294967295 เหมือนกันทุกยี่ห้อ (ค่า 32 บิตตาม RFC 2328)
          - ปฏิเสธคีย์ที่ทำให้ค่าออกนอกช่วงตั้งแต่ตอนพิมพ์ ค่าเดิมจึงคงอยู่เสมอ
          ด่านจริงอยู่ที่ validate_ospf_area ฝั่ง backend */}
      <div className="interface-configuration-form-field">
        <label className="data-label">Area</label>
        <input
          type="text"
          inputMode="numeric"
          placeholder="0"
          value={values.area}
          onChange={(event) => {
            if (acceptsOspfAreaInput(event.target.value)) setField("area", event.target.value);
          }}
          required
        />
      </div>

      {/* ตัวเลือกขา/IP ที่จะประกาศเข้า OSPF - โมเดลเดียวกับฟอร์ม RIP ทั้งสองยี่ห้อ
          แล้ว: Any/Specific คู่กับ dropdown ติ๊กช่องตัวเดียว (Juniper เพิ่ง
          ได้ Any/Specific รอบนี้ เดิมมีแต่ Specific)

          Juniper ติ๊กเป็น "ชื่อขา" เพราะ OSPF ของ Junos ผูกต่อ interface ตรง ๆ
          ส่วน Cisco ติ๊กเป็น "IP" แล้วฟอร์มคำนวณ network+wildcard ให้เอง เพราะ
          IOS ผูกต่อ network ไม่ใช่ต่อขา */}
      <div className="interface-configuration-form-field">
        <label className="data-label">{isJuniper ? "Interfaces to advertise into OSPF" : "Networks to advertise into OSPF"}</label>
        <div className="segmented-control">
          <input
            type="radio"
            id="ospf-scope-any"
            name="ospf-scope-mode"
            value="any"
            checked={values.scopeMode === "any"}
            onChange={(event) => setField("scopeMode", event.target.value)}
          />
          <label htmlFor="ospf-scope-any">Any (all internal interfaces)</label>
          <input
            type="radio"
            id="ospf-scope-specific"
            name="ospf-scope-mode"
            value="specific"
            checked={values.scopeMode === "specific"}
            onChange={(event) => setField("scopeMode", event.target.value)}
          />
          <label htmlFor="ospf-scope-specific">Specific</label>
        </div>
      </div>

      {values.scopeMode === "specific" && (
        <div className="interface-configuration-form-field">
          <label className="data-label">{isJuniper ? "Interface" : "IP"}</label>
          <CheckboxDropdown ariaLabel={isJuniper ? "Select interfaces for OSPF" : "Select IPs for OSPF"} summary={<>
              <input
                type="text"
                readOnly
                tabIndex={-1}
                aria-label={isJuniper ? "Selected Interfaces" : "Selected IPs"}
                placeholder={isJuniper ? "-- Add Interface --" : "-- Add IP --"}
                value={pickerOptions
                  .filter((option) => selected.includes(option.value))
                  .map((option) => option.label)
                  .join(", ")}
              />
            </>}>
            <div className="zone-interface-picker-options">
              {ifLoading && <div className="field-hint">Loading interface information...</div>}
              {!ifLoading && pickerOptions.length === 0 && (
                <div className="field-hint">
                  {isJuniper ? "No selectable interfaces found" : "No selectable IPs found"}
                </div>
              )}
              {pickerOptions.map((option) => (
                <label key={option.value} className="zone-interface-picker-option">
                  <input
                    type="checkbox"
                    checked={selected.includes(option.value)}
                    disabled={submitting}
                    onChange={() => toggleSelection(option.value)}
                  />
                  {option.label}
                  {option.missing && <span className="field-hint">(Configured on device, not found in current list)</span>}
                </label>
              ))}
            </div>
          </CheckboxDropdown>
        </div>
      )}

      {/* Juniper: "Passive Interface Default" เป็น software-defined concept
          (Junos ไม่มี "default" จริง - mark ทีละ interface เอง ดู
          handleSubmitJuniper) - UI/behavior mirror Cisco ทุกประการตามสเปกข้อ
          5.2: เปิด toggle แล้วทุก interface ที่เลือกไว้ด้านบนเป็น passive โดย
          default ทันที มีตารางให้ติ๊ก "ปลด Passive" เฉพาะตัวที่ต้องการให้ active
          toggle ในตาราง (ทั้ง 2 ยี่ห้อ) แสดงเป็น "เปิด = passive" ตามที่ user ขอ -
          ทุกขาเปิดไว้ก่อน ปิดเฉพาะขาที่ไม่อยาก passive - state ยังเก็บเป็น
          noPassiveInterfaces เหมือนเดิม แค่กลับค่า checked ตอนแสดงผล */}
      {isJuniper ? (
        <>
          <div className="interface-configuration-form-field">
            <label className="data-label">Passive All Interfacs</label>
            <div className="toggle-switch-container">
              <input
                type="checkbox"
                checked={values.passiveInterfaceDefault}
                onChange={(event) => setField("passiveInterfaceDefault", event.target.checked)}
                id="ospfPassiveDefaultJuniper"
              />
              <label className="toggleSwitch" htmlFor="ospfPassiveDefaultJuniper"></label>
            </div>
          </div>

          {values.passiveInterfaceDefault && announcedRows.some((row) => row.interfaceName) && (
            <div className="interface-configuration-form-field">
              <label className="data-label">Passive Interfaces Lists</label>
              <table className="form-interface-add-list">
                <tbody>
                  {announcedRows.filter((row) => row.interfaceName).map(({ interfaceName: ifaceName }) => (
                    <tr key={ifaceName}>
                      <td>{ifaceName}</td>
                      <td>
                        <div className="toggle-switch-container">
                          <input
                            type="checkbox"
                            checked={!values.noPassiveInterfaces.includes(ifaceName)}
                            onChange={() => toggleNoPassive(ifaceName)}
                            id={`nopassive-juniper-${ifaceName}`}
                          />
                          <label className="toggleSwitch" htmlFor={`nopassive-juniper-${ifaceName}`}></label>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      ) : (
        <>
          <div className="interface-configuration-form-field">
            <label className="data-label">Passive All Interfacs</label>
            <div className="toggle-switch-container">
              <input
                type="checkbox"
                checked={values.passiveInterfaceDefault}
                onChange={(event) => setField("passiveInterfaceDefault", event.target.checked)}
                id="ospfPassiveDefault"
              />
              <label className="toggleSwitch" htmlFor="ospfPassiveDefault"></label>
            </div>
          </div>

          {values.passiveInterfaceDefault && (
            <div className="interface-configuration-form-field">
              <label className="data-label">Passive Interfaces Lists</label>
              {announcedRows.length === 0 ? (
                <span className="field-hint">
                  No interface found bound to the networks above (please select an IP matching an actual interface).
                </span>
              ) : (
                <table className="form-interface-add-list">
                  <tbody>
                    {announcedRows.filter((row) => row.interfaceName).map((row) => (
                      <tr key={row.interfaceName}>
                        <td>[{row.network}] {row.interfaceName}</td>
                        <td>
                          <div className="toggle-switch-container">
                            <input
                              type="checkbox"
                              checked={!values.noPassiveInterfaces.includes(row.interfaceName)}
                              onChange={() => toggleNoPassive(row.interfaceName)}
                              id={`nopassive-${row.interfaceName}`}
                            />
                            <label className="toggleSwitch" htmlFor={`nopassive-${row.interfaceName}`}></label>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          )}
        </>
      )}

      <div className="interface-configuration-form-field">
        <label className="data-label">Default-information Originate</label>
        <div className="toggle-switch-container">
          <input
            type="checkbox"
            checked={values.defaultInformationOriginate}
            onChange={(event) => setField("defaultInformationOriginate", event.target.checked)}
            id="ospfDefOr"
          />
          <label className="toggleSwitch" htmlFor="ospfDefOr"></label>
        </div>
      </div>

      <div className="interface-configuration-form-field">
        <label className="data-label">Redistribute Static</label>
        <div className="toggle-switch-container">
          <input
            type="checkbox"
            checked={values.redistributeStatic}
            onChange={(event) => setField("redistributeStatic", event.target.checked)}
            id="ospfRedistStatic"
          />
          <label className="toggleSwitch" htmlFor="ospfRedistStatic"></label>
        </div>
      </div>

      <div className="interface-configuration-form-field">
        <label className="data-label">Redistribute RIP</label>
        <div className="toggle-switch-container">
          <input
            type="checkbox"
            checked={values.redistributeRip}
            onChange={(event) => setField("redistributeRip", event.target.checked)}
            id="ospfRedistRip"
          />
          <label className="toggleSwitch" htmlFor="ospfRedistRip"></label>
        </div>
      </div>

      <div className="interface-form-btn-container">
        <button type="submit" className="btn btn-primary" disabled={submitting}>
          {submitting ? "Sending..." : "Apply"}
        </button>
      </div>
    </form>
  );
}
