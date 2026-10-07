import { isJuniperSelectableInterfaceUnit } from "./interfaceKind.js";

export const LOCAL_DHCP_GROUP = "CM-DHCP";
const array = (value) => value == null ? [] : Array.isArray(value) ? value : [value];

export function localInterfaceParameters(name) {
  const match = /^([A-Za-z][A-Za-z0-9_/-]*)(?:\.(\d+))?$/.exec(String(name).trim());
  if (!match || match[1] === "all") return null;
  const unit = Number(match[2] || 0);
  if (!Number.isSafeInteger(unit) || unit > 4294967295) return null;
  return {name: `${match[1]}.${unit}`, unit};
}

// (2026-09) แทนที่ readLocalDhcpMembers เดิม (flat array รวมทุก group เข้าด้วยกัน
// + editable gate จากชื่อ group ตรงๆ) - group เป็น identity จริงของ Junos (เขียน/
// อ่านที่ group ไหนมีผลต่อ config จริง) จึงห้าม flatten ข้าม group เด็ดขาด และ
// editable ต้องมาจาก "parser/writer รองรับรูปร่างนี้จริงไหม" ไม่ใช่จากชื่อ group -
// Brownfield group ทุกชื่อจึงแก้ไขสมาชิกปกติได้เหมือน CM-DHCP ทุกประการ (upto/
// exclude ก็รองรับแล้วเช่นกัน ไม่ใช่ "special" ที่ต้อง read-only อีกต่อไป) เหลือแค่
// สมาชิกที่มีทั้ง upto และ exclude พร้อมกัน (รูปแบบที่ writer ปฏิเสธ - ดู
// juniper_junos.py's _checked_local_dhcp_members) หรือชื่อที่ parse เป็น
// type/id.unit ไม่ได้สะอาด ที่ยังต้อง read-only จริงๆ
export function readLocalDhcpGroups(result) {
  const groups = result?.payload?.data?.configuration?.system?.services?.["dhcp-local-server"]?.group;
  return array(groups).filter((group) => group?.name).map((group) => {
    const members = array(group.interface).map((entry) => {
      const name = typeof entry === "string" ? entry : entry?.name;
      const parsed = localInterfaceParameters(name || "");
      const upto = (typeof entry === "object" && entry !== null && entry.upto) || null;
      const exclude = typeof entry === "object" && entry !== null && Object.hasOwn(entry, "exclude");
      return {
        key: `${group.name}::${name}`,
        name,
        upto,
        exclude,
        editable: Boolean(parsed) && parsed.name === name && !(upto && exclude),
        raw: entry,
      };
    }).filter((member) => member.name);
    return {name: group.name, members, raw: group};
  });
}

// dropdown ตัวเลือก "Start Interface" สำหรับกลุ่มที่กำลังแก้ (groupName) - ตัด
// interface ที่:
//  - เป็น DHCP Relay leg อยู่แล้ว (mutual exclusion จริงของ Junos ที่ยืนยันแล้ว -
//    ดู planning/HANDOFF.md "DHCP Local Server")
//  - เป็นสมาชิกของ group อื่นอยู่แล้ว (ยังไม่เคยยืนยันกับอุปกรณ์จริงว่า Junos ห้าม
//    interface เดียวอยู่หลาย local-server group พร้อมกันจริงไหม - เลือก fail-closed
//    เป็นค่าเริ่มต้นที่ปลอดภัยกว่าไว้ก่อน)
// การกันเพิ่มซ้ำ "ภายใน" กลุ่มเดียวกัน (สมาชิกเดิมของกลุ่มนี้เองที่ยังแสดงในฟอร์ม)
// ปล่อยให้ผู้เรียก (DhcpLocalGroupPanel) จัดการตอน render แต่ละ <option> เอง
// (disable ตัวที่แถวอื่นในกลุ่มเดียวกันเลือกไปแล้ว) เพื่อให้แถวที่กำลังแก้ยังเห็น
// ค่าตัวเองอยู่ในรายการได้เสมอ
export function localInterfaceOptions(interfaceRows, groupName, allGroups, relayInterfaces) {
  const usedByOtherGroups = new Set(
    (allGroups || [])
      .filter((group) => group.name !== groupName)
      .flatMap((group) => group.members.map((member) => member.name))
  );
  const blocked = new Set([...(relayInterfaces || []), ...usedByOtherGroups]);
  const fromTelemetry = array(interfaceRows)
    .map((row) => localInterfaceParameters(row?.name)?.name)
    .filter((name) => name && isJuniperSelectableInterfaceUnit(name));
  return [...new Set(fromTelemetry)].filter((name) => !blocked.has(name)).sort();
}

// (2026-09) แทนที่ localDhcpChanges เดิม (flat string array, group="CM-DHCP" ตายตัว)
// - คำนวณ delta ของ "กลุ่มเดียว" จาก draft rows ของฟอร์ม ({name, mode, upto}) เทียบ
// กับ baselineMembers ที่อ่านมาจากอุปกรณ์ตอนโหลด/refresh คืน {group, members,
// previous_members, changed} พร้อม validate ครบ (unique, selectable, ไม่ชน relay,
// range ต้องมี Up To) - สมาชิกเดิมที่ยังอยู่ (ไม่ว่าจะแก้ไข upto/exclude หรือไม่)
// ไม่ต้องผ่านด่าน selectable/relay ซ้ำ (แก้ไขค่าที่มีอยู่แล้วได้เสมอ ด่านนั้นมีไว้
// กันแค่ "เพิ่มใหม่" เท่านั้น)
export function localGroupChanges(groupName, baselineMembers, draftRows, options, relayInterfaces, preservedMembers = []) {
  const requestedFromDraft = draftRows
    .map((row) => ({
      name: (row.name || "").trim(),
      upto: row.mode === "range" ? (row.upto || "").trim() || null : null,
      exclude: row.mode === "exclude",
    }))
    .filter((row) => row.name);
  const requested = [
    ...requestedFromDraft,
    ...preservedMembers.map(({name, upto, exclude}) => ({name, upto: upto || null, exclude: Boolean(exclude)})),
  ];

  const names = requested.map((row) => row.name);
  if (new Set(names).size !== names.length) throw new Error("Local DHCP interfaces must be unique");

  const previousByName = new Map(baselineMembers.map((member) => [member.name, member]));
  for (const row of requested) {
    if (previousByName.has(row.name)) continue; // editing an existing member is always allowed
    if (!options.includes(row.name)) throw new Error(`Interface ${row.name} is not in the selectable list`);
    if ((relayInterfaces || []).includes(row.name)) throw new Error(`Interface ${row.name} is already configured as DHCP Relay`);
  }
  for (const row of draftRows) {
    if (row.name?.trim() && row.mode === "range" && !row.upto?.trim()) {
      throw new Error("Up To interface is required for a range entry");
    }
  }

  const previous_members = baselineMembers.map(({name, upto, exclude}) => ({name, upto, exclude}));
  const requestedByName = new Map(requested.map((row) => [row.name, row]));
  const changed = previous_members.some((member) => {
    const next = requestedByName.get(member.name);
    return !next || next.upto !== member.upto || next.exclude !== member.exclude;
  }) || requested.some((row) => !previousByName.has(row.name));

  return {group: groupName, members: requested, previous_members, changed};
}
