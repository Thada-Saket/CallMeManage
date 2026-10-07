import DismissibleError from "../../DismissibleError";
import { useEffect, useRef, useState } from "react";
import { runDeviceCommand } from "../../../api/api_devices";
import getDeviceInformation from "../../../hooks/getDeviceInformation";
import { buildRoutingPickerOptions, networkAddressOf, selectAnyRoutingNetworks } from "../../../utils/routingNetworkOptions";
import { normalizeIP } from "../../../utils/normalizeIP";
import { normalizeSubnet } from "../../../utils/normalizeSubnet";
import CheckboxDropdown from "../../common/CheckboxDropdown";

// pre-fill จาก currentRule = ผลลัพธ์ parseRipSummary() ใน rip_route.jsx ตรงๆ
// (version/autoSummary/redistributeStatic/defaultInformationOriginate/entries) -
// null = ยังไม่มี RIP process เลย (ฟอร์มว่างเปล่า) - entries เป็นทั้ง network
// address (Cisco) หรือชื่อ interface (Juniper) อยู่แล้วแล้วแต่ยี่ห้อ ตรงกับที่
// values.networks ต้องการพอดีไม่ว่ายี่ห้อไหน (set_rip_routing's networks param
// ความหมายต่างกันตามยี่ห้อ แต่ entries สร้างมาให้ตรงกับความหมายนั้นแล้วตั้งแต่
// parseRipSummary) - scopeMode ล็อกเป็น "specific" เสมอถ้ามี process อยู่แล้ว
// เหมือน OSPF (ไม่ใช้ "any" เพราะคำนวณใหม่จาก interface ปัจจุบันอาจไม่ตรงกับที่
// ตั้งไว้จริง)
function buildInitialValues(currentRule) {
  if (!currentRule) {
    return {
      scopeMode: "any",
      networks: [],
      version: "2",
      noAutoSummary: true,
      defaultInformationOriginate: false,
      redistributeStatic: false,
      passiveInterfaceDefault: false,
      noPassiveInterfaces: [],
    };
  }
  return {
    scopeMode: "specific",
    networks: currentRule.entries?.length > 0 ? currentRule.entries : [],
    version: currentRule.version === "1" ? "1" : "2",
    noAutoSummary: !currentRule.autoSummary,
    defaultInformationOriginate: !!currentRule.defaultInformationOriginate,
    redistributeStatic: !!currentRule.redistributeStatic,
    passiveInterfaceDefault:
      !!currentRule.passiveInterfaceDefault || (currentRule.passiveInterfaces || []).length > 0,
    noPassiveInterfaces: currentRule.noPassiveInterfaces || [],
  };
}

// ตรงกับ set_rip_routing(networks: list[str], version=2, auto_summary=False,
// default_information_originate=False)
// currentRule = เรียกแบบใหม่ (Cisco, inline form ใต้ toggle "Enable RIP" -
// ไม่มีปุ่ม Cancel เพราะปิดฟอร์มด้วย toggle แทน) / editTarget+onClose = เรียก
// แบบเดิม (Juniper, formMode replace ทั้งหน้า - ยังต้องมีปุ่ม Cancel ให้ปิดฟอร์ม
// กลับไปได้ ไม่งั้นไม่มีทางออกจากฟอร์มเลยถ้าไม่ submit)
export default function RipRouteFormModal({ devId, vendor, currentRule = null, editTarget = null, onClose = null, onSaved }) {
  const target = currentRule ?? editTarget;
  const isEdit = !!target;
  const isJuniper = vendor === "juniper";
  const [values, setValues] = useState(buildInitialValues(target));
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const explicitPassivePrefilled = useRef(false);
  const scopePrefilled = useRef(false);

  const { data: ifData, loading: ifLoading } = getDeviceInformation(devId, "get_ip_interface_brief");
  const interfaceRows = ifData?.normalized ? ifData.result : [];
  // Juniper's set_rip_routing ต้องการ**ชื่อ interface** ตรงๆ (ผูก RIP ต่อ
  // interface - เขียนเป็น <neighbor><name>ge-0/0/1.0</name></neighbor>) ต่างจาก
  // Cisco ที่ networks เป็น**network address** (ผูก RIP ต่อ network ที่ interface
  // สังกัดอยู่) - ก่อนหน้านี้ฟอร์มนี้ไม่เคย vendor-aware เลย ส่ง network address
  // ("10.0.10.0" จาก networkAddressOf) ให้ Juniper เสมอ กลายเป็นสร้าง neighbor
  // ชื่อ "10.0.10.0" ที่ไม่มีอยู่จริงบนอุปกรณ์ - เจอบั๊กนี้ตอน cross-check กับ
  // backend's set_rip_routing signature (networks ความหมายต่างกันตามยี่ห้อ)

  function setField(name, value) {
    setValues((prev) => ({ ...prev, [name]: value }));
  }

  // เลือกด้วย dropdown ติ๊กช่องตัวเดียว รูปแบบเดียวกับ Interface Members ของ
  // zoneInterfacesFormModal (ใช้ class .zone-interface-picker ชุดเดิมทั้งหมด) -
  // เลิกใช้โมเดลเพิ่มทีละแถวด้วยปุ่ม +/- แล้ว
  const selectedNetworks = values.networks.filter(Boolean);

  function toggleNetwork(value) {
    setField(
      "networks",
      selectedNetworks.includes(value)
        ? selectedNetworks.filter((entry) => entry !== value)
        : [...selectedNetworks, value]
    );
  }

  const pickerOptions = buildRoutingPickerOptions({ interfaceRows, selected: selectedNetworks, isJuniper });

  function getCiscoAnnouncedRows(networks) {
    const rows = [];
    const seenInterfaces = new Set();
    for (const network of networks) {
      const matches = interfaceRows.filter((row) => {
        const ip = normalizeIP(row?.ip);
        const subnet = normalizeSubnet(row?.subnet);
        if (!ip || ip === "-" || !subnet) return false;
        const subnetNetwork = networkAddressOf(ip, subnet.prefix);
        const firstOctet = Number(ip.split(".")[0]);
        const classfulPrefix = firstOctet < 128 ? 8 : firstOctet < 192 ? 16 : 24;
        const classfulNetwork = networkAddressOf(ip, classfulPrefix);
        return network === subnetNetwork || network === classfulNetwork;
      });
      if (matches.length === 0) {
        rows.push({ network, interfaceName: "" });
        continue;
      }
      for (const match of matches) {
        if (!match?.name || seenInterfaces.has(match.name)) continue;
        seenInterfaces.add(match.name);
        rows.push({ network, interfaceName: match.name });
      }
    }
    return rows;
  }

  const effectiveNetworks = values.scopeMode === "any"
    ? selectAnyRoutingNetworks({ interfaceRows, isJuniper })
    : selectedNetworks;
  const ciscoAnnouncedRows = isJuniper ? [] : getCiscoAnnouncedRows(effectiveNetworks);

  // Edit: ถ้า network ที่อ่านจาก Cisco ครบเท่ากับทุกวงภายในที่โหมด Any จะเลือก
  // ให้แสดง Any ตามความหมายจริง ไม่บังคับกลับไป Specific เพียงเพราะเป็น Edit
  useEffect(() => {
    if (isJuniper || scopePrefilled.current || ifLoading || !ifData?.normalized || !target) return;
    scopePrefilled.current = true;
    const configured = target.entries || [];
    const allInternal = selectAnyRoutingNetworks({ interfaceRows, isJuniper: false });
    const isCovered = (network) => {
      const firstOctet = Number(network.split(".")[0]);
      const classfulPrefix = firstOctet < 128 ? 8 : firstOctet < 192 ? 16 : 24;
      const classfulNetwork = networkAddressOf(network, classfulPrefix);
      return configured.includes(network) || configured.includes(classfulNetwork);
    };
    const configuredIsRelevant = (statement) => allInternal.some((network) => {
      const firstOctet = Number(network.split(".")[0]);
      const classfulPrefix = firstOctet < 128 ? 8 : firstOctet < 192 ? 16 : 24;
      return statement === network || statement === networkAddressOf(network, classfulPrefix);
    });
    if (
      allInternal.length > 0 &&
      allInternal.every(isCovered) &&
      configured.every(configuredIsRelevant)
    ) {
      setValues((prev) => ({ ...prev, scopeMode: "any" }));
    }
  }, [ifData?.normalized, ifLoading, interfaceRows, isJuniper, target]);

  // Brownfield แบบ `passive-interface <name>` ไม่มี default flag แต่สามารถแทน
  // ความหมายเดิมด้วย UI แบบ OSPF ได้โดยเปิด Default และยกเว้น interface อื่นทั้งหมด
  useEffect(() => {
    if (isJuniper || explicitPassivePrefilled.current || ifLoading || !ifData?.normalized || !target) return;
    const explicitPassive = target.passiveInterfaces || [];
    if (target.passiveInterfaceDefault || explicitPassive.length === 0) {
      explicitPassivePrefilled.current = true;
      return;
    }
    const configuredRows = getCiscoAnnouncedRows(selectedNetworks);
    if (configuredRows.some((row) => !row.interfaceName)) return;
    explicitPassivePrefilled.current = true;
    const passiveSet = new Set(explicitPassive);
    setValues((prev) => ({
      ...prev,
      passiveInterfaceDefault: true,
      noPassiveInterfaces: configuredRows
        .map((row) => row.interfaceName)
        .filter((name) => !passiveSet.has(name)),
    }));
    // โหลดเพียงครั้งเดียวแล้วห้ามย้อนมาทับค่าที่ผู้ใช้กำลังแก้
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ifData?.normalized, ifLoading]);

  function toggleNoPassive(interfaceName) {
    setValues((prev) => ({
      ...prev,
      noPassiveInterfaces: prev.noPassiveInterfaces.includes(interfaceName)
        ? prev.noPassiveInterfaces.filter((name) => name !== interfaceName)
        : [...prev.noPassiveInterfaces, interfaceName],
    }));
  }

  async function handleSubmit(event) {
    event.preventDefault();
    setError("");

    let networks;
    if (values.scopeMode === "any") {
      networks = selectAnyRoutingNetworks({ interfaceRows, isJuniper });
      if (networks.length === 0) {
        setError("No internal (private) interfaces found - try selecting Specific instead");
        return;
      }
    } else {
      networks = selectedNetworks;
      if (networks.length === 0) {
        setError(isJuniper ? "Select at least one interface" : "Select at least one IP address");
        return;
      }
    }

    setSubmitting(true);
    try {
      // คำสั่งเดียวจบทั้งเปิดใช้ครั้งแรกและแก้ไขของเดิม - set_rip_routing ของทั้ง
      // สองยี่ห้อเขียนด้วย nc:operation="replace" แล้ว จึงนิยาม RIP ทั้งก้อนใน RPC
      // เดียว ของเดิมที่ไม่ได้ส่งมาด้วยหายไปเองอย่าง atomic
      //
      // เดิมยิง 3 คำสั่งเรียงกัน (validate -> remove -> set -> redistribute) ซึ่ง
      // ถ้าล้มกลางทางจะเหลือ config ไม่ครบหรือ RIP หายทั้งก้อนแบบที่ผู้ใช้กู้เองไม่ได้
      // - ตอนนี้ไม่มีขั้นลบนำหน้าแล้วจึงไม่ต้อง validate ล่วงหน้าอีก (ค่าที่ผิดถูก
      // ปฏิเสธก่อนแตะอุปกรณ์อยู่แล้วโดย build_payload ฝั่ง backend) และ redistribute
      // static ก็อยู่ใน RPC เดียวกันแล้ว ไม่ติ๊ก = ถูกล้างออกด้วย replace เอง
      const parameters = {
        networks,
        version: Number(values.version),
        auto_summary: !values.noAutoSummary,
        default_information_originate: values.defaultInformationOriginate,
        redistribute_static: values.redistributeStatic,
      };
      if (!isJuniper) {
        const announced = getCiscoAnnouncedRows(networks);
        const unresolved = announced.filter((row) => !row.interfaceName).map((row) => row.network);
        if (values.passiveInterfaceDefault && unresolved.length > 0) {
          setError(`Cannot identify the interface for: ${unresolved.join(", ")}. Refresh and try again.`);
          return;
        }
        const configuredInterfaces = new Set(announced.map((row) => row.interfaceName).filter(Boolean));
        const noPassive = new Set(
          values.noPassiveInterfaces.filter((name) => configuredInterfaces.has(name))
        );
        // IOS-XE รุ่นนี้ไม่รับ disable/passive-interface ผ่าน NETCONF แม้ CLI จะ
        // แสดง `no passive-interface`. เขียนรายชื่อขาที่ต้อง Passive แบบ explicit
        // แทน ซึ่งให้ forwarding/RIP behavior เดียวกับ default + exception
        parameters.passive_interfaces = values.passiveInterfaceDefault
          ? [...configuredInterfaces].filter((name) => !noPassive.has(name))
          : [];
      }
      await runDeviceCommand(devId, "set_rip_routing", parameters);
      onSaved();
    } catch (err) {
      setError(err.detail || (isEdit ? "Failed to edit RIP routing" : "Failed to configure RIP routing"));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form onSubmit={handleSubmit}>
      {error && <DismissibleError message={error} onDismiss={() => setError("")} />}

      <div className="interface-configuration-form-field">
        <label className="data-label">Networks to advertise into RIP</label>
        <div className="segmented-control">
          <input
            type="radio"
            id="rip-scope-any"
            name="rip-scope-mode"
            value="any"
            checked={values.scopeMode === "any"}
            onChange={(event) => setField("scopeMode", event.target.value)}
          />
          <label htmlFor="rip-scope-any">Any (all internal interfaces)</label>
          <input
            type="radio"
            id="rip-scope-specific"
            name="rip-scope-mode"
            value="specific"
            checked={values.scopeMode === "specific"}
            onChange={(event) => setField("scopeMode", event.target.value)}
          />
          <label htmlFor="rip-scope-specific">Specific</label>
        </div>
      </div>

      {values.scopeMode === "specific" && (
        <div className="interface-configuration-form-field">
          <label className="data-label">{isJuniper ? "Interfaces in RIP" : "IPs in RIP"}</label>
          <CheckboxDropdown ariaLabel={isJuniper ? "Select interfaces for RIP" : "Select IPs for RIP"} summary={<>
              <input
                type="text"
                readOnly
                tabIndex={-1}
                aria-label={isJuniper ? "Selected Interfaces" : "Selected IPs"}
                placeholder={isJuniper ? "-- Add Interface --" : "-- Add IP --"}
                value={pickerOptions
                  .filter((option) => selectedNetworks.includes(option.value))
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
                    checked={selectedNetworks.includes(option.value)}
                    disabled={submitting}
                    onChange={() => toggleNetwork(option.value)}
                  />
                  {option.label}
                  {option.missing && <span className="field-hint">(Configured on device, not found in current list)</span>}
                </label>
              ))}
            </div>
          </CheckboxDropdown>
        </div>
      )}

      <div className="interface-configuration-form-field">
        <label className="data-label">RIP Version 2 (Recommended)</label>
        <div className="toggle-switch-container">
          <input
            type="checkbox"
            id="ripVersion2"
            checked={values.version === "2"}
            onChange={(event) => setField("version", event.target.checked ? "2" : "1")}
          />
          <label className="toggleSwitch" htmlFor="ripVersion2"></label>
        </div>
      </div>

      {/* Junos ไม่มี auto-summary concept แบบ Cisco เลย - set_rip_routing ฝั่ง
          Juniper raise ValueError ทันทีถ้า auto_summary=true (noAutoSummary
          ปิด/unchecked) - ซ่อน toggle นี้ไปเลยสำหรับ Juniper กันกดพลาดแล้ว submit
          พัง (ค่า noAutoSummary ยังคง true เสมอในสถานะเริ่มต้น ปลอดภัยอยู่แล้ว) */}
      {!isJuniper && (
        <div className="interface-configuration-form-field">
          <label className="data-label">No Auto Summary</label>
          <div className="toggle-switch-container">
            <input
              type="checkbox"
              checked={values.noAutoSummary}
              onChange={(event) => setField("noAutoSummary", event.target.checked)}
              id="noAutoSum"
            />
            <label className="toggleSwitch" htmlFor="noAutoSum"></label>
          </div>
        </div>
      )}

      {/* Junos RIP default route origination implement แล้ว (2026-07-29 - เดิม
          set_rip_routing ฝั่ง Juniper raise ValueError ทันทีถ้า
          default_information_originate=true เลยซ่อน toggle นี้ไว้ก่อน) - สร้าง
          policy-statement "EXPORT-DEFAULT-RIP" (route-filter 0.0.0.0/0 exact)
          แยกต่างหาก ผูกเป็น export เส้นที่ 2 ของ group */}
      <div className="interface-configuration-form-field">
        <label className="data-label">Default-information Originate</label>
        <div className="toggle-switch-container">
          <input
            type="checkbox"
            checked={values.defaultInformationOriginate}
            onChange={(event) => setField("defaultInformationOriginate", event.target.checked)}
            id="ripDefOr"
          />
          <label className="toggleSwitch" htmlFor="ripDefOr"></label>
        </div>
      </div>

      <div className="interface-configuration-form-field">
        <label className="data-label">Redistribute Static</label>
        <div className="toggle-switch-container">
          <input
            type="checkbox"
            checked={values.redistributeStatic}
            onChange={(event) => setField("redistributeStatic", event.target.checked)}
            id="ripRedistStatic"
          />
          <label className="toggleSwitch" htmlFor="ripRedistStatic"></label>
        </div>
      </div>

      {!isJuniper && (
        <>
          <div className="interface-configuration-form-field">
            <label className="data-label">Passive Interface Default</label>
            <div className="toggle-switch-container">
              <input
                type="checkbox"
                checked={values.passiveInterfaceDefault}
                onChange={(event) => setField("passiveInterfaceDefault", event.target.checked)}
                id="ripPassiveDefault"
              />
              <label className="toggleSwitch" htmlFor="ripPassiveDefault"></label>
            </div>
          </div>

          {values.passiveInterfaceDefault && (
            <div className="interface-configuration-form-field">
              <label className="data-label">No Passive</label>
              {ciscoAnnouncedRows.filter((row) => row.interfaceName).length === 0 ? (
                <span className="field-hint">
                  No interface found bound to the networks above (please select an IP matching an actual interface).
                </span>
              ) : (
                <table className="form-interface-add-list">
                  <tbody>
                    {ciscoAnnouncedRows.filter((row) => row.interfaceName).map((row) => (
                      <tr key={row.interfaceName}>
                        <td>[{row.network}] {row.interfaceName}</td>
                        <td>
                          <div className="toggle-switch-container">
                            <input
                              type="checkbox"
                              checked={values.noPassiveInterfaces.includes(row.interfaceName)}
                              onChange={() => toggleNoPassive(row.interfaceName)}
                              id={`rip-no-passive-${row.interfaceName}`}
                            />
                            <label className="toggleSwitch" htmlFor={`rip-no-passive-${row.interfaceName}`}></label>
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

      <div className="interface-form-btn-container">
        <button type="submit" className="btn btn-primary" disabled={submitting}>
          {submitting ? "Sending..." : "Apply"}
        </button>
        {onClose && (
          <button type="button" className="btn btn-ghost" onClick={onClose}>
            Cancel
          </button>
        )}
      </div>
    </form>
  );
}
