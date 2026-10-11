import { splitInterfaceName } from "./interfaceName";

// ตาราง static route แสดง 1 แถวต่อ 1 next-hop แต่ Cisco/Juniper เก็บทุก next-hop ไว้ใต้
// prefix เดียว (fwd-list / leaf-list next-hop) - ลบหรือแก้แถวเดียวแบบทั้ง prefix จะลบ
// next-hop ตัวอื่นทิ้งไปด้วย (เช่น default route เส้นหลักหายตอนลบเส้นสำรอง) จึงระบุ
// next-hop ของแถวนั้นไปให้ translator เมื่อ prefix นี้ยังมีแถวอื่นอยู่ ถ้าเป็นแถวสุดท้าย
// ไม่ระบุ = ลบ/แก้ทั้ง prefix เหมือนเดิม (ไม่ทิ้ง prefix เปล่าที่ไม่มี next-hop ไว้)
export function hasSiblingNextHops(route, routes) {
  if (!route || !Array.isArray(routes)) return false;
  return routes.filter((other) => other.prefix === route.prefix).length > 1;
}

// prefix ("replace_" ตอน Edit, "" ตอน Delete) ใช้ชื่อ parameter เดียวกับ set_static_route
export function staticRouteTargetParameters(route, prefix = "") {
  if (route?.nextHop) return { [`${prefix}next_hop`]: route.nextHop };
  if (route?.iface) {
    const { interfaceType, interfaceId } = splitInterfaceName(route.iface);
    return { [`${prefix}interface_type`]: interfaceType, [`${prefix}interface_id`]: interfaceId };
  }
  return {};
}

// Huawei: ifName เป็นส่วนหนึ่งของ key srRoute ส่งค่าที่อ่านกลับมาจากอุปกรณ์ไปตรง ๆ
// (ไม่มีค่า = translator ใช้ Invalid0 ตามที่ set_static_route เขียน)
export function huaweiRouteIfNameParameters(route, prefix = "") {
  if (!route?.ifName) return {};
  const { interfaceType, interfaceId } = splitInterfaceName(route.ifName);
  return { [`${prefix}interface_type`]: interfaceType, [`${prefix}interface_id`]: interfaceId };
}
