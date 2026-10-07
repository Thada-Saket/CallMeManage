import { resolveCiscoProfileObjects, resolveJuniperProfileObjects } from "./securityProfileObjects.js";

function ensureArray(value) {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

const PFS_LABEL = {
  group1: "Group 1", group2: "Group 2", group5: "Group 5", group14: "Group 14",
  group15: "Group 15", group16: "Group 16", group19: "Group 19", group20: "Group 20",
  group21: "Group 21", group24: "Group 24",
};

// Junos: security/ike (proposal/policy/gateway) + security/ipsec (proposal/
// policy) - ตรงกับที่ create_security_profile เขียน โดยชื่อ object ย่อยทุกตัว
// derive จาก base name เดียวกันเสมอ (`{name}-IKE-PROP`/`-IKE-POLICY`/`-GATEWAY`/
// `-IPSEC-PROP`/`-IPSEC-POLICY`) - เดิน gateway list ก่อน (1 gateway = 1
// profile) แล้ว join กับ proposal/policy อื่นด้วยการ derive ชื่อกลับ **สำคัญ**:
// ต่างจาก Cisco - fullName ของ Juniper ต้องเป็น "base name" เดิม (ไม่ใช่ object
// name เต็มบนอุปกรณ์ตัวใดตัวหนึ่ง) เพราะ create_security_tunnel ฝั่ง Juniper รับ
// ipsec_profile เป็น base name แล้วไป derive ชื่อ gateway/policy เองข้างในอีกที
// (ไม่เหมือน Cisco ที่ ipsec_profile เป็นชื่อ object บนอุปกรณ์ตรงๆ)
// (bug 92) แปลงชื่อ algorithm ที่อ่านจากอุปกรณ์ กลับเป็น enum ที่ฟอร์มใช้
//
// ปัญหาเดิม: ฟอร์ม "แก้ไข" reset ทุกอย่างเป็น System Recommend เพราะ parser คืนชื่อ
// Junos-native ("aes-256-cbc") ที่ไม่ตรง enum ของฟอร์ม ("aes-cbc-256") ถ้า pre-fill
// ตรง ๆ จะโดน pydantic ปฏิเสธ - แต่การ reset ทำให้ผู้ใช้ที่ตั้งใจแก้แค่ฝั่ง IPsec
// โดนเขียนทับค่า IKEv2 ที่ตั้งไว้ไปด้วย ซึ่งเสียหายกว่ามาก
// ทางแก้ที่ถูกคือ map กลับ ไม่ใช่ทิ้งค่าแล้ว reset
//
// Cisco เขียน element ด้วย enum ของฟอร์มอยู่แล้ว (<aes-cbc-256/>) จึงไม่ต้อง map
const JUNOS_TO_FORM = {
  ikeEncryption: {
    "3des-cbc": "en-3des", "des-cbc": "des",
    "aes-128-cbc": "aes-cbc-128", "aes-192-cbc": "aes-cbc-192", "aes-256-cbc": "aes-cbc-256",
    "aes-128-gcm": "aes-gcm-128", "aes-256-gcm": "aes-gcm-256",
  },
  ikeIntegrity: { md5: "md5", sha1: "sha1", "sha-256": "sha256", "sha-384": "sha384", "sha-512": "sha512" },
  ipsecIntegrity: {
    "hmac-md5-96": "esp-md5-hmac", "hmac-sha1-96": "esp-sha-hmac",
    "hmac-sha-256-128": "esp-sha256-hmac", "hmac-sha-384": "esp-sha384-hmac",
    "hmac-sha-512": "esp-sha512-hmac",
  },
};

const JUNOS_GROUP_TO_FORM = {
  group1: "one", group2: "two", group5: "five", group14: "fourteen", group15: "fifteen",
  group16: "sixteen", group19: "nineteen", group20: "twenty", group21: "twenty-one",
  group24: "twenty-four",
};

function parseJuniperSecurityProfiles(result) {
  const security = result?.payload?.data?.configuration?.security || {};
  const ike = security.ike || {};
  const ipsec = security.ipsec || {};

  const ikePolicyByName = {};
  for (const p of ensureArray(ike.policy)) if (p?.name) ikePolicyByName[p.name] = p;
  const ipsecPolicyByName = {};
  for (const p of ensureArray(ipsec.policy)) if (p?.name) ipsecPolicyByName[p.name] = p;

  const resolveObjects = resolveJuniperProfileObjects(security);
  return ensureArray(ike.gateway).map((gateway) => {
    const gatewayName = gateway?.name || "";
    const baseName = gatewayName.replace(/-GATEWAY$/, "") || gatewayName;
    // ชื่อตามแบบแผนของระบบ - ใช้ตัดสินแค่ว่าแถวนี้ "สร้างจากระบบหรือเปล่า" (managed) เท่านั้น
    const ipsecPolicyMatch = ipsecPolicyByName[`${baseName}-IPSEC-POLICY`];
    const ikePolicyMatch = ikePolicyByName[`${baseName}-IKE-POLICY`];
    const addresses = ensureArray(gateway?.address);
    // ค่าจริงทุกชั้นมาจาก object ที่ resolver ไล่ตามความสัมพันธ์จริงบนอุปกรณ์ (gateway -> ike policy ->
    // proposal, vpn -> ipsec policy -> proposal) ไม่ใช่การเดาชื่อ - เดิมหา proposal ด้วยชื่อ `{base}-IKE-PROP`
    // ทำให้ profile ที่ชื่อ object ไม่ตรงแบบแผนโชว์ค่าว่างแล้วฟอร์มแอบเปลี่ยนเป็น System Recommend
    const real = resolveObjects(gateway);
    const pfsGroup = real.raw.pfsGroup;
    const ipsecEncRaw = real.raw.ipsecEncryption || "";
    return {
      name: baseName,
      fullName: baseName,
      // (bug 67 ต่อ / เคส B) "ชุดนี้สร้างจากระบบหรือเปล่า" - remove_security_profile กับ
      // create_security_profile derive ชื่อ object ย่อยทุกตัวจาก base name เดียว
      // (`-GATEWAY`/`-IKE-POLICY`/`-IPSEC-POLICY`/…) ถ้าของจริงบนอุปกรณ์ไม่ได้ตั้งชื่อ
      // ตามแบบแผนนี้ คำสั่งลบจะไปลบชื่อที่ไม่มีอยู่จริง ซึ่ง NETCONF `remove` ถือว่า
      // สำเร็จ (ไม่ error เมื่อไม่มี node) = หน้าเว็บขึ้นเขียวทั้งที่อุปกรณ์ไม่ถูกแตะเลย
      // ต้องรู้ให้ได้ตั้งแต่ตอน parse ว่าแถวไหนเป็นของระบบ ไม่ใช่ปล่อยให้ผู้ใช้ไปกดแล้ว
      // เจอผลลวง - gateway ที่ไม่ได้ลงท้าย `-GATEWAY` หรือไม่มี policy คู่ของมันครบ
      // แปลว่าตั้งจาก CLI / ติดมาก่อน onboard
      managed: /-GATEWAY$/.test(gatewayName) && Boolean(ikePolicyMatch) && Boolean(ipsecPolicyMatch),
      peerIp: addresses[0] || "",
      // ชื่อ object จริงทุกตัว + ส่วนที่แก้ได้ + แผนลบ (ดู securityProfileObjects.js) - ใช้กับแถวที่ไม่ได้
      // สร้างจากระบบ ซึ่งต้องแก้/ลบด้วยชื่อจริง ไม่ใช่ชื่อที่ derive จากชื่อที่แสดง
      real,
      // (เคส C) external-interface ที่ gateway ผูกอยู่จริง - อยู่ใน reply ตัวเดียวกันนี้
      // มาตลอด (parseSecurityTunnels.js อ่านค่านี้อยู่แล้ว) แต่ที่นี่ไม่เคยเอาออกมา
      // ฟอร์มแก้ไขจึงเริ่มด้วยช่องว่างแล้วเดาค่าให้เองจาก zone WAN - ถ้าของจริงผูกกับขาอื่น
      // ผู้ใช้ที่เข้ามาแก้แค่ PFS กด Save แล้ว gateway ย้ายขาเงียบ ๆ ทั้งที่ไม่ได้ตั้งใจ
      // (create_security_profile เขียน gateway ด้วย nc:operation="replace" ทุกครั้ง
      // external-interface จึงถูกเขียนทับด้วยค่าในฟอร์มเสมอ)
      wanInterface: gateway?.["external-interface"] || "",
      encryption: ipsecEncRaw || "-",
      integrity: real.raw.ipsecIntegrity || "-",
      mode: "Tunnel",
      pfs: pfsGroup ? PFS_LABEL[pfsGroup] || pfsGroup : "-",
      // (bug 92) ค่าในรูป enum ของฟอร์ม สำหรับ pre-fill ตอนกดแก้ไข
      form: {
        ikev2Encryption: JUNOS_TO_FORM.ikeEncryption[real.raw.ikev2Encryption[0]] || null,
        ikev2Integrity: JUNOS_TO_FORM.ikeIntegrity[real.raw.ikev2Integrity[0]] || null,
        ikev2Group: JUNOS_GROUP_TO_FORM[real.raw.ikev2Group[0]] || null,
        ipsecEncryption: ipsecEncRaw || null,   // Junos ใช้ชื่อเดียวกับตัวเลือกในฟอร์มอยู่แล้ว
        ipsecIntegrity: JUNOS_TO_FORM.ipsecIntegrity[real.raw.ipsecIntegrity] || null,
        pfsGroup: pfsGroup || null,
      },
    };
  });
}

// อ่านสดจาก get_security_profile_information - ดึงแค่ 3 ส่วนที่พอสรุปเป็นตาราง
// ได้ (ikev2/profile ให้ peer IP + keyring name, ipsec/transform-set ให้
// encryption/integrity/mode, ipsec/profile เป็นจุดเชื่อม 2 อันข้างต้น + pfs) -
// ไม่ดึง ikev2 proposal/policy/keyring เพราะเป็นรายละเอียดชั้นในที่ไม่โชว์ในตาราง
// สรุป (เหมือน ACL page ที่โชว์แค่ระดับ ACE ไม่ลงรายละเอียด object ย่อยกว่านั้น)
// export ไว้ให้ security_tunnelFormModal.jsx เอาไปทำ dropdown เลือก security
// profile ได้ด้วย (ต้องการ fullName - ชื่อ ipsec-profile เต็มๆ บนอุปกรณ์ - ไป
// ส่งเป็น ipsec_profile param ของ create_security_tunnel ส่วน name ที่ตัด
// suffix แล้วมีไว้โชว์ผู้ใช้เฉยๆ)
export function parseSecurityProfiles(result) {
  if (result?.vendor === "juniper") {
    try {
      return parseJuniperSecurityProfiles(result);
    } catch {
      return null;
    }
  }
  try {
    const crypto = result?.payload?.data?.native?.crypto;
    if (!crypto) return [];

    const ikev2ByName = {};
    for (const profile of ensureArray(crypto?.ikev2?.profile)) {
      if (profile?.name) ikev2ByName[profile.name] = profile;
    }
    const transformSetByTag = {};
    for (const ts of ensureArray(crypto?.ipsec?.["transform-set"])) {
      if (ts?.tag) transformSetByTag[ts.tag] = ts;
    }

    const resolveObjects = resolveCiscoProfileObjects(crypto);
    return ensureArray(crypto?.ipsec?.profile).map((profile) => {
      const fullName = profile?.name || "";
      const name = fullName.replace(/-IPSEC-PROFILE$/, "") || fullName;
      const set = profile?.set || {};
      const ts = transformSetByTag[set["transform-set"]] || {};
      const rawIpsecEncryption = ts?.esp || "";
      const rawIpsecKeySize = ts?.["key-bit"] ? String(ts["key-bit"]) : null;
      // IOS XE รองรับการเขียนค่าเดียวกันได้สองรูปแบบ เช่น `esp-aes` + key-bit 256
      // และ `esp-256-aes` ให้หน้าเว็บใช้รูป canonical เดียวกันเพื่อแสดงผลและ pre-fill
      // ได้ตรงกัน โดยไม่เปลี่ยนความหมายของ config บนอุปกรณ์
      const sizedAes = rawIpsecEncryption === "esp-aes" && ["192", "256"].includes(rawIpsecKeySize);
      const ipsecEncryption = sizedAes ? `esp-${rawIpsecKeySize}-aes` : rawIpsecEncryption;
      const ipsecKeySize = sizedAes ? null : rawIpsecKeySize;
      const ikev2Profile = ikev2ByName[set["ikev2-profile"]] || {};
      const peerIp = ikev2Profile?.match?.identity?.remote?.address?.ipv4?.["ipv4-address"] || "";
      const modeRaw = ts?.mode && "transport-choice" in ts.mode ? "transport" : "tunnel";
      const pfsGroup = set?.pfs?.group;
      // ค่าจริงของชั้น IKEv2 มาจาก policy/proposal ที่ resolver ไล่ให้ (ไม่ใช่การเดาชื่อ `{name}-IKEV2-POLICY`)
      // Cisco เก็บ enum เป็นชื่อ element ว่าง (<aes-cbc-256/>) resolver ดึง key ออกมาให้แล้ว และ GCM ที่ใช้ prf
      // แทน integrity (bug 90) ก็รวมอยู่ใน raw.ikev2Integrity แล้ว
      const real = resolveObjects(profile);
      return {
        name,
        fullName,
        // (bug 67 ต่อ / เคส B) ดูคอมเมนต์ฝั่ง Juniper ด้านบน - ฝั่ง Cisco ตรวจจาก
        // ชื่อ ipsec profile เองบวกกับ 2 ตัวที่มันอ้างถึง ซึ่งต้องเป็นชื่อที่
        // create_security_profile ตั้งไว้ทั้งคู่ (`-IPSEC-PROP` / `-IKEV2-PROFILE`)
        managed:
          /-IPSEC-PROFILE$/.test(fullName)
          && set["transform-set"] === `${name}-IPSEC-PROP`
          && set["ikev2-profile"] === `${name}-IKEV2-PROFILE`,
        // match address เป็น list ได้ (หลาย peer) - ตัวแรกที่อ่านได้ใช้แสดงในตาราง ที่เหลืออยู่ใน real.peerIps
        peerIp: peerIp || real.peerIps[0] || "",
        real,
        encryption: ipsecEncryption || "-",
        integrity: ts?.["esp-hmac"] || "-",
        mode: modeRaw === "transport" ? "Transport" : "Tunnel",
        modeRaw,
        pfs: pfsGroup ? PFS_LABEL[pfsGroup] || pfsGroup : "-",
        pfsGroupRaw: pfsGroup || "",
        // (bug 92) ค่าในรูป enum ของฟอร์ม สำหรับ pre-fill ตอนกดแก้ไข
        form: {
          ikev2Encryption: real.raw.ikev2Encryption[0] || null,
          ikev2Integrity: real.raw.ikev2Integrity[0] || null,
          ikev2Group: real.raw.ikev2Group[0] || null,
          ipsecEncryption: ipsecEncryption || null,
          ipsecKeySize,
          ipsecIntegrity: ts?.["esp-hmac"] || null,
          pfsGroup: pfsGroup || null,
        },
      };
    });
  } catch {
    return null;
  }
}
