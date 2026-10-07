export function naturalCompare(a, b) {
  return String(a || "").localeCompare(String(b || ""), undefined, {
    numeric: true,
    sensitivity: "base",
  });
}

function ensureArray(val) {
  if (val === undefined || val === null) return [];
  return Array.isArray(val) ? val : [val];
}

function extractAclName(dirObj) {
  if (!dirObj || typeof dirObj !== "object") return null;
  const val = dirObj?.acl?.["acl-name"] ?? dirObj?.["acl-name"] ?? null;
  return val != null && String(val).trim() ? String(val).trim() : null;
}

/**
 * แปลงผลลัพธ์ get_switchport_information ของ Cisco เป็นรายการ interface ทั้งหมด
 * พร้อม Inbound และ Outbound ACL ที่ผูกอยู่ (ถ้ามี)
 *
 * รองรับทั้ง:
 * 1. Normalized switchport rows array จาก backend (Cisco)
 * 2. Generic / un-normalized structure (payload.data.native.interface)
 *
 * @param {Object|Array} result ข้อมูล switchport จาก backend
 * @returns {Array<{ interfaceName: string, interfaceType: string, interfaceId: string, inboundAcl: string|null, outboundAcl: string|null }>}
 */
export function parseInterfaceAclBindings(result) {
  const data = result?.result !== undefined ? result.result : result;
  if (!data) return [];

  const interfaces = [];

  // Case 1: Normalized switchport rows array from backend (Cisco)
  if (Array.isArray(data)) {
    for (const row of data) {
      const ifName = (row?.name || "").trim();
      if (!ifName) continue;
      const raw = row?.raw || {};
      const ag = raw?.ip?.["access-group"];
      const inAcl = extractAclName(ag?.in);
      const outAcl = extractAclName(ag?.out);
      interfaces.push({
        interfaceName: ifName,
        interfaceType: "",
        interfaceId: "",
        inboundAcl: inAcl,
        outboundAcl: outAcl,
      });
    }
    return interfaces.sort((a, b) => naturalCompare(a.interfaceName, b.interfaceName));
  }

  // Case 2: Generic / un-normalized structure (payload.data.native.interface or native.interface)
  const nativeIf = data?.payload?.data?.native?.interface || data?.native?.interface;
  if (nativeIf && typeof nativeIf === "object") {
    for (const [ifType, ifList] of Object.entries(nativeIf)) {
      for (const iface of ensureArray(ifList)) {
        const ifId = iface?.name != null ? String(iface.name).trim() : "";
        const ifName = ifId ? `${ifType}${ifId}` : ifType;
        const ag = iface?.ip?.["access-group"];
        const inAcl = extractAclName(ag?.in);
        const outAcl = extractAclName(ag?.out);
        interfaces.push({
          interfaceName: ifName,
          interfaceType: ifType,
          interfaceId: ifId,
          inboundAcl: inAcl,
          outboundAcl: outAcl,
        });
      }
    }
    return interfaces.sort((a, b) => naturalCompare(a.interfaceName, b.interfaceName));
  }

  // Case 3: Junos interfaces structure (configuration.interfaces.interface)
  const junosIf =
    data?.payload?.data?.configuration?.interfaces?.interface ||
    data?.configuration?.interfaces?.interface ||
    data?.payload?.data?.interfaces?.interface ||
    data?.interfaces?.interface;
  if (junosIf) {
    for (const iface of ensureArray(junosIf)) {
      const ifType = (iface?.name || "").trim();
      if (!ifType) continue;
      const units = ensureArray(iface?.unit);
      for (const unit of units) {
        const unitName = (unit?.name != null ? String(unit.name) : "").trim();
        const ifName = unitName ? `${ifType}.${unitName}` : ifType;
        const filter = unit?.family?.inet?.filter;
        let inAcl = null;
        let outAcl = null;
        let isRepresentable = true;
        const unsupportedReasons = [];

        if (filter && typeof filter === "object") {
          if (filter.input) {
            if (typeof filter.input === "object") {
              const fn = filter.input["filter-name"] ?? filter.input["#text"];
              inAcl = fn ? String(fn).trim() : null;
            } else if (typeof filter.input === "string") {
              inAcl = filter.input.trim();
            }
          }
          if (filter.output) {
            if (typeof filter.output === "object") {
              const fn = filter.output["filter-name"] ?? filter.output["#text"];
              outAcl = fn ? String(fn).trim() : null;
            } else if (typeof filter.output === "string") {
              outAcl = filter.output.trim();
            }
          }
          if (filter["input-list"] || filter["input-chain"]) {
            isRepresentable = false;
            unsupportedReasons.push("Interface has input-list/input-chain");
          }
          if (filter["output-list"]) {
            isRepresentable = false;
            unsupportedReasons.push("Interface has output-list");
          }
        }

        interfaces.push({
          interfaceName: ifName,
          interfaceType: ifType,
          unit: unitName,
          inboundAcl: inAcl || null,
          outboundAcl: outAcl || null,
          isRepresentable,
          unsupportedReasons,
        });
      }
    }
    return interfaces.sort((a, b) => naturalCompare(a.interfaceName, b.interfaceName));
  }

  return [];
}

/**
 * รวมข้อมูลการผูก Interface ของแต่ละ ACL เพื่อนำไปแสดงในตารางสรุป
 * รองรับทั้ง ACL ที่มี rules ในตาราง และ Brownfield ACL ที่ผูกอยู่กับ interface จริง
 *
 * @param {Array} aclRules รายการ rules จาก parseAclRules
 * @param {Array} allInterfaces รายการ interface ทั้งหมดจาก parseInterfaceAclBindings
 * @returns {Array<{ aclName: string, inboundInterfaces: string[], outboundInterfaces: string[], isBrownfieldOnly: boolean }>}
 */
export function aggregateAclBindings(aclRules, allInterfaces) {
  const aclNamesSet = new Set();
  for (const r of aclRules || []) {
    if (r?.aclName) aclNamesSet.add(String(r.aclName).trim());
  }
  for (const iface of allInterfaces || []) {
    if (iface.inboundAcl) aclNamesSet.add(iface.inboundAcl);
    if (iface.outboundAcl) aclNamesSet.add(iface.outboundAcl);
  }

  const sortedNames = Array.from(aclNamesSet).sort(naturalCompare);
  return sortedNames.map((aclName) => {
    const inbound = (allInterfaces || [])
      .filter((i) => i.inboundAcl === aclName)
      .map((i) => i.interfaceName)
      .sort(naturalCompare);
    const outbound = (allInterfaces || [])
      .filter((i) => i.outboundAcl === aclName)
      .map((i) => i.interfaceName)
      .sort(naturalCompare);
    const isBrownfieldOnly = !(aclRules || []).some((r) => String(r.aclName).trim() === aclName);
    return {
      aclName,
      inboundInterfaces: inbound,
      outboundInterfaces: outbound,
      isBrownfieldOnly,
    };
  });
}
