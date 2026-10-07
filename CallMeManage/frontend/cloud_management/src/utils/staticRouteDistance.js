const DEFAULT_STATIC_ROUTE_DISTANCE = {
  cisco: "1",
  juniper: "5",
};

// อุปกรณ์ไม่จำเป็นต้องเก็บ AD/preference leaf เมื่อใช้ค่า default จึงแยกค่าที่ใช้
// แสดงออกจากค่าดิบ ห้ามเติมกลับลง route.distance เพราะ Edit แล้ว Save จะเปลี่ยน
// implicit default ให้กลายเป็นค่าที่เขียนไว้ใน configuration โดยไม่จำเป็น
export function effectiveStaticRouteDistance(value, vendor) {
  const text = value === undefined || value === null ? "" : String(value).trim();
  if (text) return text;
  return DEFAULT_STATIC_ROUTE_DISTANCE[String(vendor || "").toLowerCase()] || "";
}

export function displayStaticRouteDistance(value, vendor) {
  return effectiveStaticRouteDistance(value, vendor) || "-";
}
