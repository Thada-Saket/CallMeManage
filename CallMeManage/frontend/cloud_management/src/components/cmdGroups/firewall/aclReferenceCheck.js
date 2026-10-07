import { runDeviceCommand } from "../../../api/api_devices.js";

export const MAX_ACL_SEQUENCE = 2147483647;

export function normalizeAclIdentity(rule, isJuniper = false) {
  if (!rule) return null;
  const aclName = (rule.aclName ?? rule.name ?? "").trim();
  if (isJuniper) {
    const termName = String(rule.termName ?? rule.term_name ?? rule.sequence ?? "").trim();
    return { isJuniper: true, aclName, termName };
  }
  const aclType = (rule.aclType ?? "extended").toLowerCase();
  const rawSeq = rule.sequence;
  const sequence = (rawSeq !== "" && rawSeq != null) ? Number(rawSeq) : null;
  return { isJuniper: false, aclType, aclName, sequence };
}

export function areAclIdentitiesEqual(idA, idB) {
  if (!idA || !idB) return false;
  if (idA.isJuniper !== idB.isJuniper) return false;
  if (idA.isJuniper) {
    return idA.aclName === idB.aclName && idA.termName === idB.termName;
  }
  return (
    idA.aclType === idB.aclType &&
    idA.aclName === idB.aclName &&
    idA.sequence === idB.sequence
  );
}

export function findAclIdentityCollision(rules, targetIdentity, ignoreIdentity = null) {
  if (!Array.isArray(rules) || !targetIdentity) return null;
  for (const r of rules) {
    const rId = normalizeAclIdentity(r, targetIdentity.isJuniper);
    if (!rId) continue;
    if (ignoreIdentity && areAclIdentitiesEqual(rId, ignoreIdentity)) {
      continue;
    }
    if (areAclIdentitiesEqual(rId, targetIdentity)) {
      return r;
    }
  }
  return null;
}

export function getNextCiscoSequence(rules, aclName, aclType = "extended") {
  const targetName = (aclName || "").trim();
  const targetType = (aclType || "extended").toLowerCase();
  if (!Array.isArray(rules) || !targetName) return 10;

  const matched = rules.filter((r) => {
    const rName = (r.aclName ?? r.name ?? "").trim();
    const rType = (r.aclType ?? "extended").toLowerCase();
    return rName === targetName && rType === targetType;
  });

  const seqs = matched
    .map((r) => Number(r.sequence))
    .filter((s) => Number.isInteger(s) && s > 0);

  if (seqs.length === 0) return 10;
  const maxSeq = Math.max(...seqs);
  const nextSeq = maxSeq + 10;
  if (nextSeq > MAX_ACL_SEQUENCE) return null;
  return nextSeq;
}

export function ruleKey(rule) {
  if (!rule) return "";
  return `${rule.aclType ? rule.aclType + "::" : ""}${rule.aclName}::${rule.sequence}`;
}

/**
 * ตรวจสอบว่ากฎที่ระบุเป็นกฎสุดท้ายของ ACL นั้นในตารางปัจจุบันหรือไม่
 * @param {Array} rules รายการกฎทั้งหมดที่ parse จาก get_acl_information
 * @param {Object} targetRule กฎที่กำลังตรวจสอบ ({ aclName, sequence, aclType, ... })
 * @returns {boolean} true ถ้าเป็นกฎเดียวที่เหลืออยู่ใน ACL นั้น, false ถ้ายังมีกฎอื่นร่วม ACL เดียวกัน หรือไม่มีกฎอยู่
 */
export function isLastAclRule(rules, targetRule) {
  if (!rules || !rules.length || !targetRule || !targetRule.aclName) return false;
  const targetKey = ruleKey(targetRule);
  const hasTarget = rules.some((r) => ruleKey(r) === targetKey);
  if (!hasTarget) return false;
  return !rules.some(
    (r) =>
      r.aclName === targetRule.aclName &&
      (r.aclType === targetRule.aclType || !targetRule.aclType) &&
      ruleKey(r) !== targetKey
  );
}

/**
 * ตรวจสอบว่า ACL บนอุปกรณ์ Cisco กำลังถูกใช้งานโดยฟีเจอร์อื่น (NAT, Interface
 * access-group, Zone-Based Firewall) หรือไม่ - ตรวจสอบผ่าน get_acl_reference_information
 * เพียงคำสั่งเดียวใน backend ภายใต้ DeviceLock เดียว
 *
 * @param {string|number} devId รหัสอุปกรณ์
 * @param {string} aclName ชื่อ ACL ที่ต้องการตรวจสอบ
 * @param {string} [aclType="extended"] ประเภท ACL (standard หรือ extended)
 * @param {Object} [options] ตัวเลือกเพิ่มเติม เช่น signal สำหรับ AbortController
 * @returns {Promise<{ known: boolean, inUse: boolean, reasons: string[], references: Object, revision: string|null, acl: Object|null }>}
 *   known:false = ตรวจสอบไม่สำเร็จ ผู้เรียกต้องปิดปุ่ม Delete แบบ fail-closed ห้ามตีความเป็น inUse:false
 */
export async function checkAclReferencesCisco(devId, aclName, aclType = "extended", options = {}) {
  if (!devId || !aclName) {
    return {
      known: true,
      inUse: false,
      reasons: [],
      references: { nat: [], interfaces: [], zbf: [] },
      revision: null,
      acl: null,
    };
  }

  const reasons = [];
  let known = true;
  let inUse = false;
  let references = { nat: [], interfaces: [], zbf: [] };
  let revision = null;
  let acl = null;

  try {
    const res = await runDeviceCommand(
      devId,
      "get_acl_reference_information",
      { name: aclName, acl_type: aclType || "extended" },
      { allowFailure: true, signal: options?.signal }
    );

    const data = res?.result;
    if (!data || data.known === false || data.ok === false) {
      return {
        known: false,
        inUse: false,
        reasons: [data?.error || data?.message || "Failed to check ACL references"],
        references,
        revision: null,
        acl: null,
      };
    }

    references = data.references || { nat: [], interfaces: [], zbf: [] };
    revision = data.revision || null;
    acl = data.acl || null;

    // 1. NAT Policy reasons
    for (const n of references.nat || []) {
      reasons.push(n.detail || `NAT Policy (${aclName})`);
    }

    // 2. Interface reasons
    for (const iface of references.interfaces || []) {
      reasons.push(`Interface ${iface.interface} (${iface.direction === "in" ? "inbound" : "outbound"})`);
    }

    // 3. Zone-Based Firewall reasons
    for (const u of references.zbf || []) {
      reasons.push(`Stateful Firewall Zone Pair "${u.zone_pair || u.zonePair}"`);
    }

    inUse = data.in_use === true || reasons.length > 0;
  } catch (err) {
    console.warn("[BUG-77] ตรวจสอบการอ้างอิง ACL ไม่สำเร็จ (fail-closed):", err);
    known = false;
    reasons.push(err?.detail?.message || err?.detail || err?.message || "Failed to read reference data from device");
  }

  return {
    known,
    inUse: reasons.length > 0 || inUse,
    reasons,
    references,
    revision,
    acl,
  };
}
