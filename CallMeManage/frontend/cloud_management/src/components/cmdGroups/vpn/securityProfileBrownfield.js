// แก้ไข Security Profile ที่ "มีอยู่บนอุปกรณ์อยู่แล้ว" (ไม่ได้สร้างจากระบบ) - แยกออกจาก
// security_profileFormModal.jsx เพราะกติกาต่างจากฟอร์มสร้าง/แก้ของที่ระบบสร้างเอง:
//
//   1. แสดง "ค่าจริง" บนอุปกรณ์เสมอ แม้ค่านั้นอยู่นอกตัวเลือกของ dropdown หรือมีหลายค่า - ไม่แอบเปลี่ยนเป็น
//      ค่า System Recommend (จอต้องตรงกับอุปกรณ์)
//   2. บันทึกโดยส่ง "เฉพาะ field ที่ผู้ใช้เปลี่ยน" เป็นคำสั่ง modify_security_profile ที่ทำงานกับชื่อ object จริง
//      ไม่เขียนทับทั้ง object - ค่าที่ไม่ได้แตะ (รวมค่าที่ฟอร์มไม่รู้จัก) จึงรอดครบ
//
// ค่าที่ไม่เปลี่ยนไม่ถูกส่งซ้ำ จึงไม่มีทางไปตายที่ Literal ของ translator เพราะค่านอกตัวเลือก

// ค่าใน <select> ที่แปลว่า "ใช้ค่าที่อยู่บนอุปกรณ์ตามเดิม" (มีหลายค่า หรือไม่มีในตัวเลือกให้เลือก)
export const DEVICE_VALUE = "__device__";

function pick(mapped, rawList) {
  if (!rawList || rawList.length === 0) return "";           // ไม่มีค่านี้บนอุปกรณ์เลย
  if (rawList.length === 1 && mapped) return mapped;
  return DEVICE_VALUE;                                       // หลายค่า หรืออ่านแล้ว map เป็นตัวเลือกไม่ได้
}

// catalog รับตัวเลือกและ recommended set จากฟอร์ม (เจ้าของค่ากลางทั้งหมด)
export function buildBrownfieldInitialValues(editTarget, catalog) {
  const { real } = editTarget;
  const raw = real.raw;
  const form = editTarget.form || {};
  const algorithm = catalog.toIpsecAlgorithm(form.ipsecEncryption, form.ipsecKeySize);
  const ikev2Encryption = pick(form.ikev2Encryption, raw.ikev2Encryption);
  const ikev2Integrity = pick(form.ikev2Integrity, raw.ikev2Integrity);
  const ikev2Group = pick(form.ikev2Group, raw.ikev2Group);
  const ipsecAlgorithm = raw.ipsecEncryption ? algorithm || DEVICE_VALUE : "";
  const ipsecIntegrity = raw.ipsecIntegrity ? form.ipsecIntegrity || DEVICE_VALUE : "";
  const ikev2IsRecommend =
    ikev2Encryption === catalog.IKEV2_RECOMMENDED.encryption
    && ikev2Integrity === catalog.IKEV2_RECOMMENDED.integrity
    && ikev2Group === catalog.IKEV2_RECOMMENDED.group;
  const ipsecIsRecommend =
    ipsecAlgorithm === catalog.IPSEC_RECOMMENDED.algorithm
    && ipsecIntegrity === catalog.IPSEC_RECOMMENDED.integrity;
  return {
    name: editTarget.name || "",
    peerIp: editTarget.peerIp || "",
    psk: "",
    wanInterface: editTarget.wanInterface || "",
    ikev2Mode: ikev2IsRecommend ? "recommend" : "custom",
    ikev2Encryption,
    ikev2Integrity,
    ikev2Group,
    ipsecMode: ipsecIsRecommend ? "recommend" : "custom",
    ipsecAlgorithm,
    ipsecIntegrity,
    enablePfs: Boolean(raw.pfsGroup),
    pfsGroup: raw.pfsGroup || "group14",
    tunnelMode: editTarget.modeRaw === "transport" ? "transport" : "tunnel",
  };
}

// เติม option "ค่าปัจจุบัน" เข้าลิสต์เมื่อค่าจริงอยู่นอกตัวเลือกที่ผ่านการกรองตามรุ่นอุปกรณ์ - ไม่งั้น <select>
// ที่ value ไม่ตรงกับ option ตัวไหนเลยจะแสดงช่องว่างทั้งที่ state ถือค่าอยู่
export function withCurrentOption(options, current, rawValues) {
  if (!current) return options;
  if (current === DEVICE_VALUE) {
    const label = rawValues && rawValues.length ? rawValues.join(", ") : "Unknown";
    return [{ value: DEVICE_VALUE, label: `Current device value: ${label}` }, ...options];
  }
  if (options.some((option) => option.value === current)) return options;
  return [{ value: current, label: `${current} (Current device value)` }, ...options];
}

const UNCHANGED_CHOICE = "Please choose a specific value - current device value has multiple values or is not in the options, so it cannot be partially edited.";

// คืน { command, params } ที่มีเฉพาะ field ที่เปลี่ยน - โยน Error ถ้าไม่มีอะไรเปลี่ยน
// หรือค่าที่เปลี่ยนไม่ครบคู่/ส่วนนั้นแก้ไม่ได้
export function buildBrownfieldModifyParams({ values, initial, editTarget, isJuniper, catalog }) {
  const { objects, sections } = editTarget.real;
  const changed = (key) => values[key] !== initial[key];
  const allow = (section) => {
    if (!sections[section]?.editable) throw new Error(sections[section]?.reason || "This section cannot be edited");
  };
  const params = isJuniper ? { gateway: objects.gateway } : { ipsec_profile: objects.ipsecProfile };
  let touched = false;

  // ---- Peer IP ----
  if (changed("peerIp")) {
    allow("peer");
    if (!values.peerIp) throw new Error("Please enter Peer IP");
    params.peer_ip = values.peerIp;
    params.old_peer_ip = initial.peerIp;
    if (!isJuniper) {
      params.ikev2_profile = objects.ikev2Profile;
      if (objects.keyring) {
        params.keyring = objects.keyring;
        params.keyring_peer = objects.keyringPeer;
      }
    }
    touched = true;
  }

  // ---- PSK: ส่งเฉพาะเมื่อผู้ใช้กรอกค่าใหม่ ----
  if (values.psk) {
    allow("psk");
    params.psk = values.psk;
    if (isJuniper) params.ike_policy = objects.ikePolicy;
    else {
      params.keyring = objects.keyring;
      params.keyring_peer = objects.keyringPeer;
      // Cisco ต้องเขียนกลับ path เดิมของ brownfield (`key`, `local-option` หรือ
      // `remote-option`) เพื่อไม่เปลี่ยนความหมายของ keyring โดยไม่ตั้งใจ
      if (editTarget.real.pskType && editTarget.real.pskType !== "key") {
        params.psk_type = editTarget.real.pskType;
      }
    }
    touched = true;
  }

  // ---- WAN interface (Junos) ----
  if (isJuniper && changed("wanInterface")) {
    if (!values.wanInterface) throw new Error("Please select WAN Interface");
    params.wan_interface = values.wanInterface;
    touched = true;
  }

  // ---- IKEv2 proposal: encryption กับ integrity/prf พึ่งกัน (GCM ห้ามมี integrity) ต้องส่งคู่กันเสมอ ----
  if (changed("ikev2Encryption") || changed("ikev2Integrity")) {
    if (!isJuniper) throw new Error("Cisco IKEv2 Proposal is a global setting. Please edit from IKEv2 Proposal table.");
    allow("ikev2");
    if ([values.ikev2Encryption, values.ikev2Integrity].some((v) => !v || v === DEVICE_VALUE)) throw new Error(UNCHANGED_CHOICE);
    params.ikev2_encryption = values.ikev2Encryption;
    params.ikev2_integrity = values.ikev2Integrity;
    touched = true;
  }
  if (changed("ikev2Group")) {
    if (!isJuniper) throw new Error("Cisco IKEv2 Proposal is a global setting. Please edit from IKEv2 Proposal table.");
    allow("ikev2");
    if (!values.ikev2Group || values.ikev2Group === DEVICE_VALUE) throw new Error(UNCHANGED_CHOICE);
    params.ikev2_group = values.ikev2Group;
    touched = true;
  }
  if (params.ikev2_encryption !== undefined || params.ikev2_group !== undefined) {
    params[isJuniper ? "ike_proposal" : "ikev2_proposal"] = isJuniper ? objects.ikeProposal : objects.ikev2Proposal;
  }

  // ---- IPsec transform-set/proposal: encryption + key size + integrity ส่งครบชุดเมื่อมีตัวใดเปลี่ยน ----
  if (changed("ipsecAlgorithm") || changed("ipsecIntegrity")) {
    allow("ipsec");
    const algo = catalog.IPSEC_ALGORITHMS.find((a) => a.value === values.ipsecAlgorithm);
    if (!algo) throw new Error(UNCHANGED_CHOICE);
    params.ipsec_encryption = algo.encryption;
    if (algo.keySize) params.ipsec_key_size = algo.keySize;
    if (!catalog.IPSEC_COMBINED_MODE.has(algo.encryption)) {
      if (!values.ipsecIntegrity || values.ipsecIntegrity === DEVICE_VALUE) throw new Error(UNCHANGED_CHOICE);
      params.ipsec_integrity = values.ipsecIntegrity;
    }
    params[isJuniper ? "ipsec_proposal" : "transform_set"] = isJuniper ? objects.ipsecProposal : objects.transformSet;
    touched = true;
  }
  if (!isJuniper && changed("tunnelMode")) {
    allow("ipsec");
    params.tunnel_mode = values.tunnelMode;
    params.transform_set = objects.transformSet;
    touched = true;
  }

  // ---- PFS ----
  if (changed("enablePfs") || (values.enablePfs && changed("pfsGroup"))) {
    allow("pfs");
    params.pfs_group = values.enablePfs ? values.pfsGroup : "none";
    if (isJuniper) params.ipsec_policy = objects.ipsecPolicy;
    touched = true;
  }

  if (!touched) throw new Error("No changes made");
  return { command: "modify_security_profile", params };
}
