function ensureArray(value) {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

// ---------- Table 2 + 3 source data ----------
// Junos: protocols/ospf/area/interface (ตรงกับที่ set_ospf_network/
// set_ospf_passive_interface/remove_ospf_interface เขียน) - ไม่มี process-id
// แบบ Cisco ส่วน router-id อยู่ routing-options คนละ subtree จึงรับเป็น optional
// parameter เพื่อไม่ทำให้ผู้เรียกเดิมที่ส่งเฉพาะ protocols (bug 91) พัง (bug 86)
// export ให้ security_tunnel.jsx ใช้ร่วม (bug 91) - ต้องรู้ว่า OSPF อ้าง interface
// ตัวไหนอยู่บ้างก่อนจะให้ลบ tunnel · ถ้า copy ตรรกะไปอีกไฟล์ วันหนึ่งโครงสร้าง XML
// เปลี่ยนจะต้องไล่แก้ 2 ที่แล้วพลาดง่าย (บทเรียนเดียวกับตอนแยก parseSecurityTunnels)
export function parseJuniperOspf(protocols, routingOptions = null) {
  const areas = ensureArray(protocols?.ospf?.area).map((area) => ({
    name: area?.name || "",
    interfaces: ensureArray(area?.interface).map((iface) => ({
      name: iface?.name || "",
      passive: "passive" in (iface || {}),
    })),
  }));
  const exportPolicies = ensureArray(protocols?.ospf?.export);
  return {
    areas,
    defaultInformationOriginate: exportPolicies.includes("EXPORT-DEFAULT"),
    redistributeStatic: exportPolicies.includes("EXPORT-STATIC-OSPF"),
    redistributeRip: exportPolicies.includes("EXPORT-RIP-OSPF"),
    routerId: routingOptions?.["router-id"] || "",
  };
}
