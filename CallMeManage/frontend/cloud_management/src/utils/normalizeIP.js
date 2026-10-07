// |====== Null IP Format ======|

// แปลงให้ถ้าค่า ip เป็น 0.0.0.0 จากการดึง ให้แปลงเป็น -
export function normalizeIP(value) {
  if (value == "0.0.0.0") return "-";
  return value.trim()
}
