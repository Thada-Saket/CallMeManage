// Cisco Zone-Based Firewall (ZBF) reader/parser - แยกออกจาก stateful.jsx (2026-09)
// เดินตาม reference chain จริงทุกชั้น: Zone Pair -> Policy Map -> ทุก class
// -> Class Map -> ACL / Protocol -> nested Class Map (ถ้ามี) ไม่มีการเดาความ
// สัมพันธ์จากชื่อ object เด็ดขาด (ของเดิม join ACL ด้วย aclByName[policyMapName]
// ซึ่งผิดทันทีที่ผู้ดูแลตั้งชื่อ ACL/Policy Map ไม่เหมือนกัน - ดู
// planning/cisco_zbf_survey_2026-09.md ส่วน Section 13)
//
// โมดูลนี้เป็น pure function ล้วน (ไม่มี hook/side effect) เพื่อให้ทดสอบตรงได้
// โดยไม่ต้อง render React - stateful.jsx import มาใช้แทนโค้ด parser เดิมที่เคย
// อยู่ในไฟล์ component

export function ensureArray(value) {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

// wildcard mask (Cisco ACL) -> prefix length เฉพาะ mask ที่ bit ต่อเนื่องจากซ้าย
// (255.255.255.0 -> /24) mask ที่ไม่ต่อเนื่อง (เช่น discontiguous wildcard) คืน null
// ฟอร์มปัจจุบันไม่มีทางสร้าง mask แบบนั้นได้เอง แต่ Brownfield อาจมี - ต้องไม่เดา
export function wildcardToPrefix(mask) {
  const octets = String(mask || "").split(".").map(Number);
  if (octets.length !== 4 || octets.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  const bits = octets.map((n) => (255 - n).toString(2).padStart(8, "0")).join("");
  if (!/^1*0*$/.test(bits)) return null;
  return bits.indexOf("0") === -1 ? 32 : bits.indexOf("0");
}

// สร้าง index ตามชื่อจาก list ใด ๆ - byName คืน object เดียวต่อชื่อ, duplicates
// เก็บชื่อที่พบมากกว่า 1 รายการ (ก้ำกึ่ง - ห้ามเลือกอันใดอันหนึ่งแทนต้อง Read-only)
// รายการที่ไม่มีชื่อ (falsy) ถูกข้าม ไม่ทำให้เกิด key ว่าง
function indexByName(list, nameFn) {
  const byName = {};
  const duplicates = new Set();
  for (const item of list) {
    const name = nameFn(item);
    if (!name) continue;
    if (Object.prototype.hasOwnProperty.call(byName, name)) {
      duplicates.add(name);
    } else {
      byName[name] = item;
    }
  }
  return { byName, duplicates };
}

// ตรวจ ACL หนึ่งตัว: คืนทั้ง entries แบบละเอียด (ทุก ACE ต้นฉบับ) และ scopes/readable
// แบบย่อสำหรับฟอร์มเดิม (permit ip <source> any เท่านั้นที่ฟอร์มรักษารูปแบบได้)
// ค่าที่ฟอร์มรักษาไม่ได้ต้องบันทึกเหตุผลต่อ sequence ไว้ ห้าม default เป็น any เงียบๆ
function parseAclDetail(acl) {
  const entries = [];
  const scopes = [];
  const details = [];
  for (const sequenceRule of ensureArray(acl?.["access-list-seq-rule"])) {
    const ace = sequenceRule?.["ace-rule"] || {};
    const sequence = sequenceRule?.sequence ?? "?";
    entries.push({
      sequence,
      action: ace.action || "",
      protocol: ace.protocol || "",
      log: "log" in ace,
      raw: ace,
    });
    if (ace.action !== "permit" || ace.protocol !== "ip" || !("dst-any" in ace)) {
      details.push(`sequence ${sequence}: only permit ip <source> any is supported`);
      continue;
    }
    if ("any" in ace) scopes.push("any");
    else if (ace["host-address"]) scopes.push(ace["host-address"] + "/32");
    else if (ace["ipv4-address"] && ace.mask) {
      const prefix = wildcardToPrefix(ace.mask);
      if (prefix === null) details.push(`sequence ${sequence}: non-contiguous wildcard mask`);
      else scopes.push(ace["ipv4-address"] + "/" + prefix);
    } else {
      details.push(`sequence ${sequence}: source address format cannot be preserved by form`);
    }
  }
  if (scopes.includes("any") && scopes.length > 1) {
    details.push("ACL combines any with other scopes, which the form cannot preserve");
  }
  const readable = details.length === 0 && scopes.length > 0;
  return { readable, scopes, details, entries };
}

function resolveAclByName(aclName, aclIndex) {
  if (aclIndex.duplicates.has(aclName)) {
    return { acl: null, reason: `More than 1 ACL named "${aclName}" found on device (ambiguous)` };
  }
  const acl = aclIndex.byName[aclName];
  if (!acl) {
    return { acl: null, reason: `ACL "${aclName}" not found on device` };
  }
  return { acl, reason: null };
}

function resolveClassMapByName(name, classMapIndex) {
  if (classMapIndex.duplicates.has(name)) {
    return { classMap: null, reason: `More than 1 Class Map named "${name}" found on device (ambiguous)` };
  }
  const cm = classMapIndex.byName[name];
  if (!cm) {
    return { classMap: null, reason: `Class Map "${name}" not found on device` };
  }
  if (cm.type !== "inspect") {
    return { classMap: null, reason: `Class Map "${name}" is not type inspect (found type="${cm.type || "-"}"), not for Zone-Based Firewall` };
  }
  return { classMap: cm, reason: null };
}

const KNOWN_MATCH_KEYS = new Set(["access-group", "protocol", "class-map"]);
const MAX_NESTED_CLASS_MAP_DEPTH = 8;

// เดิน Class Map แบบ recursive (รองรับ nested match class-map) - visitedPath กัน
// วนซ้ำ (cycle) และจำกัดความลึกไม่ให้ recursion ไม่มีที่สิ้นสุด ไม่มีตัวอย่างจริง
// สำหรับ nested class-map ในโปรเจกต์นี้ (ดู tests/fixtures/cisco_zbf/README.md)
// - fixture ที่ทดสอบ path นี้ต้องระบุ synthetic ชัดเจน
function walkClassMap(name, classMapIndex, aclIndex, visitedPath) {
  const chainReasons = [];
  const unsupportedReasons = [];

  if (visitedPath.includes(name)) {
    chainReasons.push(`Circular reference (cycle) detected in Class Map: ${[...visitedPath, name].join(" → ")}`);
    return { classMapModel: null, acls: [], reachableAcls: [], chainReasons, unsupportedReasons };
  }
  if (visitedPath.length >= MAX_NESTED_CLASS_MAP_DEPTH) {
    chainReasons.push(`Class Map nested beyond ${MAX_NESTED_CLASS_MAP_DEPTH} levels ("${name}"), not supported`);
    return { classMapModel: null, acls: [], reachableAcls: [], chainReasons, unsupportedReasons };
  }

  const { classMap: cm, reason: resolveReason } = resolveClassMapByName(name, classMapIndex);
  if (!cm) {
    chainReasons.push(resolveReason);
    return { classMapModel: null, acls: [], reachableAcls: [], chainReasons, unsupportedReasons };
  }

  const aclNames = ensureArray(cm?.match?.["access-group"]?.name).filter(Boolean);
  const protocolEntries = ensureArray(cm?.match?.protocol?.["protocols-list"]);
  const protocols = protocolEntries.map((p) => p?.protocols).filter(Boolean);
  const nestedClassMapNames = ensureArray(cm?.match?.["class-map"]).filter(Boolean);
  const unknownMatchKeys = Object.keys(cm?.match || {}).filter((k) => !KNOWN_MATCH_KEYS.has(k));

  if (unknownMatchKeys.length > 0) {
    unsupportedReasons.push(`Class Map "${name}" has unsupported match criteria: ${unknownMatchKeys.join(", ")}`);
  }
  if (protocols.length > 0) {
    unsupportedReasons.push(`Class Map "${name}" has match protocol/application ("${protocols.join(", ")}") which is not supported by current form`);
  }
  if (nestedClassMapNames.length > 0) {
    unsupportedReasons.push(`Class Map "${name}" references nested Class Map (${nestedClassMapNames.join(", ")}) which is not supported by current form`);
  }

  const acls = [];
  for (const aclName of aclNames) {
    const { acl, reason } = resolveAclByName(aclName, aclIndex);
    if (!acl) {
      chainReasons.push(`Class Map "${name}" references ACL "${aclName}" but ${reason}`);
      continue;
    }
    const parsed = parseAclDetail(acl);
    acls.push({ name: aclName, readable: parsed.readable, scopes: parsed.scopes, entries: parsed.entries, details: parsed.details });
    if (!parsed.readable) {
      unsupportedReasons.push(...parsed.details.map((d) => `ACL "${aclName}" (via Class Map "${name}"): ${d}`));
    }
  }

  const nestedClassMaps = [];
  const reachableAcls = [...acls];
  const nestedPath = [...visitedPath, name];
  for (const nestedName of nestedClassMapNames) {
    const nestedResult = walkClassMap(nestedName, classMapIndex, aclIndex, nestedPath);
    nestedClassMaps.push({ name: nestedName, ...nestedResult });
    chainReasons.push(...nestedResult.chainReasons.map((r) => `(nested "${nestedName}" of "${name}") ${r}`));
    unsupportedReasons.push(...nestedResult.unsupportedReasons.map((r) => `(nested "${nestedName}" of "${name}") ${r}`));
    // ACL ที่ถูกอ้างผ่าน nested Class Map ต้องนับเป็น "reachable" ของ class นี้ด้วย
    // (ไม่ใช่แค่ acls ตรงๆ) - ใช้ตอนตรวจ sharedObjects/ACL-in-use ให้ครบ
    reachableAcls.push(...nestedResult.reachableAcls);
  }

  return {
    classMapModel: {
      name: cm.name,
      type: cm.type || "",
      prematch: cm.prematch || "",
      aclNames,
      protocols,
      nestedClassMapNames,
      nestedClassMaps: nestedClassMaps.map((n) => n.classMapModel).filter(Boolean),
      unknownMatchKeys,
    },
    acls,
    reachableAcls,
    chainReasons,
    unsupportedReasons,
  };
}

const KNOWN_CLASS_ENTRY_KEYS = new Set(["name", "type", "policy"]);
const KNOWN_POLICY_ACTION_KEYS = new Set(["action", "log", "parameter-map"]);

// สร้างโมเดลของ Policy Map Class หนึ่งตัว (ทั้ง class-default และ class ที่มีชื่อ)
// class-default ไม่มี Class Map object ให้ต้องไม่รายงานว่า "หา Class Map ไม่เจอ"
function buildClassModel(classEntry, classMapIndex, aclIndex) {
  const rawName = classEntry?.name || "";
  const isClassDefault = rawName === "class-default";
  const policyBlock = classEntry?.policy || {};
  const action = policyBlock.action ?? null;
  const log = "log" in policyBlock;
  const parameterMap = policyBlock["parameter-map"] ?? null;

  const unknownClassKeys = Object.keys(classEntry || {}).filter((k) => !KNOWN_CLASS_ENTRY_KEYS.has(k));
  const unknownPolicyKeys = Object.keys(policyBlock).filter((k) => !KNOWN_POLICY_ACTION_KEYS.has(k));

  const chainReasons = [];
  const unsupportedReasons = [];
  unknownClassKeys.forEach((k) => unsupportedReasons.push(`Policy Map Class "${rawName || "(unnamed)"}" has unsupported field: ${k}`));
  unknownPolicyKeys.forEach((k) => unsupportedReasons.push(`Policy Map Class "${rawName || "(unnamed)"}" has unsupported policy field: ${k}`));
  if (parameterMap) {
    unsupportedReasons.push(`Policy Map Class "${rawName}" has parameter-map ("${parameterMap}") which is not supported by current form`);
  }

  let classMap = null;
  let acls = [];
  let reachableAcls = [];
  if (!isClassDefault) {
    if (!rawName) {
      chainReasons.push("Found non-default class without a name (empty name)");
    } else {
      const walked = walkClassMap(rawName, classMapIndex, aclIndex, []);
      classMap = walked.classMapModel;
      acls = walked.acls;
      reachableAcls = walked.reachableAcls;
      chainReasons.push(...walked.chainReasons);
      unsupportedReasons.push(...walked.unsupportedReasons);
      if (classEntry?.type && classMap && classEntry.type !== classMap.type) {
        chainReasons.push(`Policy Map Class "${rawName}" specifies type="${classEntry.type}" but actual Class Map is type="${classMap.type}"`);
      }
    }
  }

  return {
    name: rawName || (isClassDefault ? "class-default" : ""),
    isClassDefault,
    type: isClassDefault ? null : classEntry?.type || null,
    action,
    log,
    parameterMap,
    classMapName: isClassDefault ? null : rawName || null,
    classMap,
    acls,
    reachableAcls,
    unknownClassKeys,
    unknownPolicyKeys,
    chainReasons,
    unsupportedReasons,
  };
}

function resolvePolicyMapByName(name, policyMapIndex) {
  if (policyMapIndex.duplicates.has(name)) {
    return { policyMap: null, reason: `More than 1 Policy Map named "${name}" found on device (ambiguous)` };
  }
  const pm = policyMapIndex.byName[name];
  if (!pm) {
    return { policyMap: null, reason: `Policy Map "${name}" not found on device` };
  }
  return { policyMap: pm, reason: null };
}

// รวบรวม membersByZone จาก native.interface (ทุก interface type: GigabitEthernet,
// Tunnel, ฯลฯ) - อ่านเหมือนเดิมทุกประการจาก parser เดิม (ยังไม่มีปัญหาที่ต้องแก้)
function buildMembersByZone(nativeInterface) {
  const membersByZone = {};
  for (const [interfaceType, rows] of Object.entries(nativeInterface || {})) {
    for (const row of ensureArray(rows)) {
      const zone = row?.["zone-member"]?.security;
      if (!zone || !row?.name) continue;
      (membersByZone[zone] ||= []).push(interfaceType + row.name);
    }
  }
  return membersByZone;
}

function buildIndexes(native) {
  const zoneIndex = indexByName(ensureArray(native?.zone?.security), (z) => z?.id);
  const zonePairIndex = indexByName(ensureArray(native?.["zone-pair"]?.security), (p) => p?.id);
  const policyMapIndex = indexByName(ensureArray(native?.policy?.["policy-map"]), (pm) => pm?.name);
  const classMapIndex = indexByName(ensureArray(native?.policy?.["class-map"]), (cm) => cm?.name);
  const aclIndex = indexByName(ensureArray(native?.ip?.["access-list"]?.extended), (acl) => acl?.name);
  const membersByZone = buildMembersByZone(native?.interface);
  return { zoneIndex, zonePairIndex, policyMapIndex, classMapIndex, aclIndex, membersByZone };
}

// เดินสร้างโมเดลดิบของ 1 Zone Pair (ยังไม่รวม sharedObjects - ต้องรู้ทุก Zone Pair
// ก่อนถึงจะบอกได้ว่า object ไหนถูกใช้ร่วมกัน) คืน object พร้อม reachedObjects
// (ชื่อ object จริงทุกตัวที่ Zone Pair นี้ไปถึงได้จริง) สำหรับ phase 2
function buildRawPolicy(pair, indexes) {
  const chainReasons = [];
  const unsupportedReasons = [];
  const name = pair?.id || "";
  const source = pair?.source || "";
  const destination = pair?.destination || "";
  const reachedObjects = []; // [{kind, name}]

  if (name && indexes.zonePairIndex.duplicates.has(name)) {
    chainReasons.push(`More than 1 Zone Pair named "${name}" found on device (ambiguous)`);
  }

  const policyMapName = pair?.["service-policy"]?.type?.inspect || "";
  let policyMap = null;
  if (!policyMapName) {
    chainReasons.push(`Zone Pair "${name}" has no service-policy type inspect attached`);
  } else {
    const resolved = resolvePolicyMapByName(policyMapName, indexes.policyMapIndex);
    policyMap = resolved.policyMap;
    if (!policyMap) {
      chainReasons.push(`Zone Pair "${name}" references Policy Map "${policyMapName}" but ${resolved.reason}`);
    } else {
      reachedObjects.push({ kind: "policy-map", name: policyMapName });
      if (policyMap.type && policyMap.type !== "inspect") {
        chainReasons.push(`Policy Map "${policyMapName}" is not type inspect (type="${policyMap.type}")`);
      }
    }
  }

  const classEntries = policyMap ? ensureArray(policyMap.class) : [];
  if (policyMap && classEntries.length === 0) {
    chainReasons.push(`Policy Map "${policyMapName}" has no classes`);
  }

  const classes = classEntries.map((entry) => buildClassModel(entry, indexes.classMapIndex, indexes.aclIndex));
  for (const cls of classes) {
    chainReasons.push(...cls.chainReasons);
    unsupportedReasons.push(...cls.unsupportedReasons);
    if (cls.classMapName) reachedObjects.push({ kind: "class-map", name: cls.classMapName });
    // reachableAcls รวม ACL ที่อ้างผ่าน nested Class Map ด้วย (ไม่ใช่แค่ cls.acls
    // ตรงๆ) - ต้องนับเป็น shared/in-use เหมือนกับที่ backend (cisco_zbf.py) ทำ
    for (const acl of cls.reachableAcls) reachedObjects.push({ kind: "acl", name: acl.name });

    function collectNested(cm) {
      if (!cm) return;
      for (const nestedName of cm.nestedClassMapNames || []) reachedObjects.push({ kind: "class-map", name: nestedName });
      for (const nested of cm.nestedClassMaps || []) collectNested(nested);
    }
    collectNested(cls.classMap);
  }

  const classDefault = classes.find((c) => c.isClassDefault) || null;
  const nonDefaultClasses = classes.filter((c) => !c.isClassDefault);

  return {
    name,
    source,
    destination,
    policyMapName,
    policyMap,
    classes,
    classDefault,
    nonDefaultClasses,
    chainReasons,
    unsupportedReasons,
    reachedObjects,
    sourceMembers: indexes.membersByZone[source] || [],
    destinationMembers: indexes.membersByZone[destination] || [],
  };
}

// ระบบเดิม (create_firewall_policy/remove_firewall_policy) derive ชื่อ ACL/Class
// Map/Policy Map เป็น FW_<ชื่อ zone-pair> ทั้งหมด - ใช้ตรวจ "รูปแบบ" เท่านั้นเพื่อ
// ตัดสินว่า Writer ปัจจุบันเขียนทับอย่างปลอดภัยได้ไหม ห้ามใช้เป็น join/lookup key
function computeSystemManagedShape(raw) {
  if (raw.nonDefaultClasses.length !== 1) return false;
  const expected = `FW_${raw.name}`;
  const cls = raw.nonDefaultClasses[0];
  if (raw.policyMapName !== expected) return false;
  if (cls.classMapName !== expected) return false;
  if (!cls.classMap || cls.classMap.prematch !== "match-any") return false;
  if (cls.acls.length !== 1 || cls.acls[0].name !== expected) return false;
  return true;
}

// เกณฑ์ editable แบบเข้มงวด (ต้องผ่านทุกข้อ) - เพราะ Writer ปัจจุบันยังใช้ชื่อ
// FW_<name> และ replace ทั้งก้อนเสมอ (ดู create_firewall_policy) - อ่านได้ครบ
// ไม่ได้แปลว่าแก้ได้ปลอดภัย ต้องพิสูจน์ว่า round-trip ผ่าน Writer ปัจจุบันได้จริง
function computeEditableChecklist(raw, systemManagedShape, _sharedObjects) {
  const blockingErrors = [];
  const preservedFields = [];
  const readOnlyReasons = [];

  if (raw.chainReasons.length > 0) {
    blockingErrors.push(...raw.chainReasons);
    readOnlyReasons.push(...raw.chainReasons);
  }
  if (raw.nonDefaultClasses.length === 0) {
    blockingErrors.push("No usable classes found (excluding class-default)");
    readOnlyReasons.push("No usable classes found (excluding class-default)");
  }

  if (!systemManagedShape) {
    preservedFields.push("Object names on device (Brownfield)");
  }
  if (raw.nonDefaultClasses.length > 1) {
    preservedFields.push(`Additional classes in Policy Map (${raw.nonDefaultClasses.length - 1} entries)`);
    readOnlyReasons.push(`More than 1 non-default class exists (${raw.nonDefaultClasses.length} entries)`);
  }
  if (raw.classDefault) {
    preservedFields.push("class-default configuration");
  }
  if (raw.unsupportedReasons.length > 0) {
    preservedFields.push(...raw.unsupportedReasons);
    readOnlyReasons.push(...raw.unsupportedReasons);
  }

  const canEdit = blockingErrors.length === 0;
  return {
    editable: canEdit,
    blockingErrors: [...new Set(blockingErrors)],
    preservedFields: [...new Set(preservedFields)],
    readOnlyReasons: [...new Set(readOnlyReasons)],
  };
}

// เดินเก็บ Application/Protocol ทั้งหมดจาก Class Map (รวม nested Class Maps)
// รักษา insertion order และตัดตัวซ้ำ
export function collectClassMapProtocols(cm) {
  if (!cm) return [];
  const protocols = [];
  const seen = new Set();
  function walk(current) {
    if (!current) return;
    for (const p of current.protocols || []) {
      if (p && !seen.has(p)) {
        seen.add(p);
        protocols.push(p);
      }
    }
    for (const nested of current.nestedClassMaps || []) {
      walk(nested);
    }
  }
  walk(cm);
  return protocols;
}

// aclScopes/aclReadable/aclDetails/action/log/applications แบบ flatten (field เดิม
// ที่ตาราง/ฟอร์มปัจจุบันใช้) - ผลิตได้เฉพาะตอนไม่กำกวมเท่านั้น (exactly 1
// non-default class) หลายอันไม่เคยเลือกอันแรกมาเป็นตัวแทนเงียบๆ
function buildFlattenedFields(raw) {
  if (raw.nonDefaultClasses.length !== 1) {
    return {
      action: null,
      log: false,
      aclReadable: false,
      aclScopes: [],
      aclDetails: raw.nonDefaultClasses.length === 0 ? [] : ["More than 1 non-default class exists; cannot clearly display a single ACL"],
      applications: [],
      applicationsKnown: false,
      applicationMode: "unknown",
    };
  }
  const cls = raw.nonDefaultClasses[0];
  const scopes = [];
  const details = [];
  let readable = cls.acls.length > 0;
  for (const acl of cls.acls) {
    scopes.push(...acl.scopes);
    details.push(...acl.details);
    if (!acl.readable) readable = false;
  }
  const cm = cls.classMap;
  const chainOk = raw.chainReasons.length === 0;
  const applications = collectClassMapProtocols(cm);
  const applicationsKnown = chainOk && !!cm && (!cm.unknownMatchKeys || cm.unknownMatchKeys.length === 0);
  const applicationMode = !applicationsKnown
    ? "unknown"
    : applications.length > 0
    ? "specific"
    : "any";

  return {
    action: cls.action ?? null,
    log: !!cls.log,
    aclReadable: readable,
    aclScopes: scopes,
    aclDetails: details,
    applications,
    applicationsKnown,
    applicationMode,
  };
}

function buildObjectNames(raw) {
  const classMaps = [];
  const acls = [];
  function collect(cls) {
    if (cls.classMapName) classMaps.push(cls.classMapName);
    for (const acl of cls.reachableAcls) acls.push(acl.name);
    function collectNested(cm) {
      if (!cm) return;
      for (const nestedName of cm.nestedClassMapNames || []) classMaps.push(nestedName);
      for (const nested of cm.nestedClassMaps || []) collectNested(nested);
    }
    collectNested(cls.classMap);
  }
  for (const cls of raw.classes) collect(cls);
  return {
    zonePair: raw.name,
    policyMap: raw.policyMapName || null,
    classMaps: [...new Set(classMaps)],
    acls: [...new Set(acls)],
  };
}

// backend (vendor_translators/cisco_zbf.py::list_cisco_zbf_policies_for_api) คือ
// แหล่งความจริงเดียวของ revision/editable/readOnlyReasons/sharedObjects เพราะ
// อ่าน running config สดทุกครั้งและใช้ authoritative graph เดียวกับที่ Edit/Delete
// จริงตรวจก่อนเขียน - ที่นี่คำนวณ "ค่าคาดเดา" ไว้ใช้แสดงผลก่อน metadata มาถึงเท่านั้น
// เมื่อมี metadata (join ด้วยชื่อ Zone Pair จริง) ต้อง "แทนที่" ค่าที่คำนวณเองเสมอ -
// ไม่มี metadata เลย = fail closed (editable บังคับ false) ห้ามเดาว่าปลอดภัย
function mapBackendSharedObject(s) {
  return { kind: s?.kind || "", name: s?.name || "", sharedWith: s?.shared_with || s?.sharedWith || [] };
}

function applyAuthoritativeZbfMetadata(policy, meta) {
  if (!meta) {
    return {
      ...policy,
      revision: null,
      editable: false,
      capabilities: { can_edit: false, can_delete: false, can_open: false },
      blockingErrors: [
        ...(policy.blockingErrors || policy.readOnlyReasons || []),
        "No verified revision data from backend for this Zone Pair (fail-closed). Please Refresh before editing/deleting.",
      ],
      readOnlyReasons: [
        ...policy.readOnlyReasons,
        "No verified revision data from backend for this Zone Pair (fail-closed). Please Refresh before editing/deleting.",
      ],
    };
  }
  const metaApps = Array.isArray(meta.applications) ? meta.applications : null;
  const metaAppsKnown = typeof meta.applications_known === "boolean" ? meta.applications_known : null;
  const metaAppMode = meta.application_mode || null;

  let applicationMode = policy.applicationMode;
  if (metaAppMode) {
    if (metaAppMode === "single" || metaAppMode === "multiple") {
      applicationMode = "specific";
    } else if (metaAppMode === "any" || metaAppMode === "legacy") {
      applicationMode = "any";
    } else if (metaAppMode === "unknown") {
      applicationMode = "unknown";
    }
  }

  const blockingErrors = Array.isArray(meta.blocking_errors) ? meta.blocking_errors : (policy.blockingErrors || []);
  const preservedFields = Array.isArray(meta.preserved_fields) ? meta.preserved_fields : (policy.preservedFields || []);
  const capabilities = meta.capabilities || {
    can_edit: meta.editable !== undefined ? !!meta.editable : blockingErrors.length === 0,
    can_delete: meta.editable !== undefined ? !!meta.editable : blockingErrors.length === 0,
    can_open: meta.editable !== undefined ? !!meta.editable : blockingErrors.length === 0,
  };

  return {
    ...policy,
    revision: meta.revision || null,
    editable: capabilities.can_edit,
    capabilities,
    blockingErrors,
    preservedFields,
    readOnlyReasons: blockingErrors.length > 0 ? blockingErrors : (Array.isArray(meta.read_only_reasons) ? meta.read_only_reasons : policy.readOnlyReasons),
    sharedObjects: Array.isArray(meta.shared_objects) ? meta.shared_objects.map(mapBackendSharedObject) : policy.sharedObjects,
    systemManagedShape: !!meta.system_managed_shape,
    chainComplete: !!meta.chain_complete,
    applications: metaApps !== null ? metaApps : policy.applications,
    applicationsKnown: metaAppsKnown !== null ? metaAppsKnown : policy.applicationsKnown,
    applicationMode,
    ciscoApplicationMode: metaAppMode || undefined,
  };
}

// อ่านสดจากอุปกรณ์ (get_firewall_information) เดินตาม reference จริงทุกชั้น -
// ไม่มี fallback ใดๆ ที่เดาความสัมพันธ์จากชื่อ - โยน Error เมื่อ native เองผิดรูป
// (ต่างจาก "ไม่มี Zone Pair เลย" ซึ่งเป็นสถานะว่างที่ถูกต้อง ต้องคืน [] ปกติ)
// zbfMetadata (2026-09) = data.zbf_metadata ที่ device_router.py แนบมาคู่กับผลของ
// get_firewall_information (ดู applyAuthoritativeZbfMetadata ด้านบน)
export function parseCiscoFirewallPolicies(result, zbfMetadata) {
  const data = result?.payload?.data;
  if (result && typeof result !== "object") {
    throw new Error("Failed to read Cisco ZBF configuration: device result is not an object");
  }
  if (!data || typeof data !== "object") {
    throw new Error("Failed to read Cisco ZBF configuration: no data in device result");
  }
  const native = data.native;
  if (native === undefined || native === null) {
    // ไม่มี <native> เลยในผลลัพธ์ - ถือเป็นค่าว่างที่ถูกต้อง (อุปกรณ์ไม่มี ZBF configured)
    return [];
  }
  if (typeof native !== "object" || Array.isArray(native)) {
    throw new Error("Failed to read Cisco ZBF configuration: malformed native structure (not an object)");
  }

  const indexes = buildIndexes(native);
  const zonePairs = ensureArray(native["zone-pair"]?.security);
  if (zonePairs.length === 0) return [];

  const rawPolicies = [];
  for (const pair of zonePairs) {
    try {
      if (pair === null || typeof pair !== "object") {
        rawPolicies.push({
          crashed: true,
          name: "",
          source: "",
          destination: "",
          reason: "A zone-pair/security entry is not a readable object",
        });
        continue;
      }
      rawPolicies.push(buildRawPolicy(pair, indexes));
    } catch (err) {
      rawPolicies.push({
        crashed: true,
        name: pair?.id || "",
        source: pair?.source || "",
        destination: pair?.destination || "",
        reason: `Error while reading this Zone Pair: ${err?.message || err}`,
      });
    }
  }

  // phase 2: reachability map ข้าม Zone Pair ทั้งหมด (ใช้ตัดสิน sharedObjects)
  // - ใช้ Set ต่อ Zone Pair กัน object ที่ถูกอ้างซ้ำหลายจุด "ภายใน" Zone Pair
  //   เดียวกันถูกนับเป็น "ใช้ร่วมกับตัวเอง"
  const reachabilityMap = new Map(); // key: `${kind}:${name}` -> Set(zonePairName)
  for (const raw of rawPolicies) {
    if (raw.crashed) continue;
    const seen = new Set();
    for (const obj of raw.reachedObjects) {
      const key = `${obj.kind}:${obj.name}`;
      if (seen.has(key)) continue;
      seen.add(key);
      if (!reachabilityMap.has(key)) reachabilityMap.set(key, new Set());
      reachabilityMap.get(key).add(raw.name);
    }
  }

  const metadataByName = new Map();
  for (const m of ensureArray(zbfMetadata)) {
    if (m && m.name) metadataByName.set(m.name, m);
  }

  const policies = rawPolicies.map((raw) => {
    if (raw.crashed) {
      return {
        name: raw.name,
        source: raw.source,
        destination: raw.destination,
        zonePairName: raw.name,
        policyMapName: null,
        classes: [],
        classDefault: null,
        objectNames: { zonePair: raw.name, policyMap: null, classMaps: [], acls: [] },
        applications: [],
        applicationsKnown: false,
        applicationMode: "unknown",
        aclScopes: [],
        sourceMembers: [],
        destinationMembers: [],
        action: null,
        log: false,
        aclReadable: false,
        aclDetails: [],
        chainComplete: false,
        readerRepresentable: false,
        systemManagedShape: false,
        revision: null,
        editable: false,
        readOnlyReasons: [raw.reason],
        unsupportedReasons: [],
        sharedObjects: [],
      };
    }

    const sharedObjects = [];
    const seenSharedKey = new Set();
    for (const obj of raw.reachedObjects) {
      const key = `${obj.kind}:${obj.name}`;
      if (seenSharedKey.has(key)) continue;
      seenSharedKey.add(key);
      const zonePairsReaching = reachabilityMap.get(key);
      if (zonePairsReaching && zonePairsReaching.size > 1) {
        sharedObjects.push({
          kind: obj.kind,
          name: obj.name,
          sharedWith: [...zonePairsReaching].filter((n) => n !== raw.name),
        });
      }
    }

    const systemManagedShape = computeSystemManagedShape(raw);
    const { editable, blockingErrors, preservedFields, readOnlyReasons } = computeEditableChecklist(raw, systemManagedShape, sharedObjects);
    const flattened = buildFlattenedFields(raw);
    const objectNames = buildObjectNames(raw);
    const chainComplete = raw.chainReasons.length === 0;

    const policy = {
      name: raw.name,
      source: raw.source,
      destination: raw.destination,
      zonePairName: raw.name,
      policyMapName: raw.policyMapName || null,
      classes: raw.classes,
      classDefault: raw.classDefault,
      objectNames,
      applications: flattened.applications,
      applicationsKnown: flattened.applicationsKnown,
      applicationMode: flattened.applicationMode,
      aclScopes: flattened.aclScopes,
      sourceMembers: raw.sourceMembers,
      destinationMembers: raw.destinationMembers,
      action: flattened.action,
      log: flattened.log,
      aclReadable: flattened.aclReadable,
      aclDetails: flattened.aclDetails,
      chainComplete,
      readerRepresentable: true,
      systemManagedShape,
      revision: null,
      editable,
      capabilities: {
        can_edit: editable,
        can_delete: editable,
        can_open: editable,
      },
      blockingErrors,
      preservedFields,
      readOnlyReasons,
      unsupportedReasons: [...new Set(raw.unsupportedReasons)],
      sharedObjects,
    };
    return applyAuthoritativeZbfMetadata(policy, metadataByName.get(raw.name));
  });

  return policies;
}

// ใช้โดยหน้า Stateless ACL (aclReferenceCheck.js) เพื่อเช็คว่า ACL ชื่อหนึ่งถูก
// Zone-Based Firewall ที่ active อยู่จริงใช้งานอยู่หรือไม่ - เดินตาม reference graph
// จริง (รวม nested Class Map ผ่าน objectNames.acls) ไม่ใช่การเดาจาก prefix ชื่อ
// เป็นแค่ UX hint เท่านั้น (backend ยังต้องปฏิเสธคำสั่งได้เสมอผ่าน
// resolve_cisco_acl_mutation_guard ใน vendor_translators/cisco_zbf.py แม้ฟังก์ชันนี้
// จะพลาดไปเพราะเหตุผลใดก็ตาม) คืน known:false เมื่ออ่าน/parse ไม่สำเร็จ (fail-closed
// - ผู้เรียกต้องปิดปุ่ม Delete/Edit เมื่อ known:false ไม่ใช่ตีความเป็น inUse:false)
export function findCiscoAclZbfUsage(result, aclName) {
  if (!aclName) return { known: true, inUse: false, usage: [] };
  let policies;
  try {
    policies = parseCiscoFirewallPolicies(result);
  } catch {
    return { known: false, inUse: false, usage: [] };
  }
  const usage = policies
    .filter((p) => p.objectNames?.acls?.includes(aclName))
    .map((p) => ({ zonePair: p.name, policyMap: p.policyMapName, source: p.source, destination: p.destination }));
  return { known: true, inUse: usage.length > 0, usage };
}
