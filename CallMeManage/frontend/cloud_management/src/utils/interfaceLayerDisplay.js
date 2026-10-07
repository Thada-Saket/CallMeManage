// ค่าที่แสดงในตาราง Interface หลักเท่านั้น - ห้ามเขียนกลับลง layerRows/raw (ข้อมูล Brownfield ที่
// Edit form ใช้สร้าง payload) และห้ามอนุมาน Layer จาก IP/ชื่อ interface/VLAN

export function buildLayerLookup(layerRows) {
  const lookup = new Map();
  for (const row of Array.isArray(layerRows) ? layerRows : []) {
    // exact name match; ชื่อซ้ำ = แถวแรกชนะ (เหมือน .find ที่ใช้กับ selectedLayer)
    if (row?.name && !lookup.has(row.name)) lookup.set(row.name, row);
  }
  return lookup;
}

const text = (value) => (typeof value === "string" ? value.trim().toLowerCase() : "");

export function displayLayer(layerRow) {
  const layer = text(layerRow?.layer);
  if (layer === "layer 2") return "Layer 2";
  if (layer === "layer 3") return "Layer 3";
  return "-";
}

export function displaySwitchportMode(layerRow) {
  const mode = text(layerRow?.mode);
  if (mode === "access") return "Access";
  if (mode === "trunk") return "Trunk";
  return "None";
}
