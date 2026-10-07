import { isJuniperSelectableInterfaceUnit } from "./interfaceKind.js";

function ensureArray(value) {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

// get_switchport_information ของ Cisco/Huawei ถูก normalize เป็นแถวกลางแล้ว
// ส่วน Juniper ยังเป็น config ดิบ จึงอ่าน family ของ logical unit โดยตรง
export function layer3StaticRouteInterfaces(result, vendor) {
  if (vendor === "juniper") {
    const interfaces = ensureArray(
      result?.payload?.data?.configuration?.interfaces?.interface
    );
    const names = [];
    for (const iface of interfaces) {
      if (!iface?.name) continue;
      for (const unit of ensureArray(iface.unit)) {
        if (!unit?.family || !Object.hasOwn(unit.family, "inet")) continue;
        if (unit.name === undefined || unit.name === null || unit.name === "") continue;
        const name = `${iface.name}.${unit.name}`;
        if (isJuniperSelectableInterfaceUnit(name)) names.push(name);
      }
    }
    return [...new Set(names)];
  }

  if (!Array.isArray(result)) return [];
  return [...new Set(
    result
      .filter((row) => row?.layer === "Layer 3" && row?.name)
      .map((row) => row.name)
  )];
}
