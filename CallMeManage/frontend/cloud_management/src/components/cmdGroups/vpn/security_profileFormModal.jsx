import DismissibleError from "../../DismissibleError";
import { useEffect, useState } from "react";
import { runDeviceCommand, validateDeviceCommand } from "../../../api/api_devices";
import getDeviceInformation from "../../../hooks/getDeviceInformation";
import IPv4Input from "../../common/IPv4Input";
import { validateIPv4Input } from "../../../utils/ipv4Input";
import { getWanZoneInterfaces } from "../../../utils/wanZoneInterfaces";
import { isJuniperSelectableInterfaceUnit } from "../../../utils/interfaceKind.js";
import { buildBrownfieldInitialValues, buildBrownfieldModifyParams, withCurrentOption } from "./securityProfileBrownfield.js";

// ตัวเลือกทั้งหมดตรงกับ enum/leaf name จริงใน Cisco-IOS-XE-crypto.yang (verify
// แล้ว ไม่เดา) - ค่าฝั่งซ้าย (value) คือสิ่งที่ต้องส่งไปเป๊ะ ฝั่งขวา (label) แปล
// ให้อ่านง่ายเฉยๆ - **ยืนยันแล้วว่าค่าเดียวกันนี้ตรงกับ Juniper's Literal choices
// ทุกตัวเป๊ะ** (create_security_profile ทั้ง 2 ยี่ห้อ ตั้งใจให้ enum ตรงกัน) เลย
// ใช้ list เดียวกันได้ทั้ง 2 ยี่ห้อ ไม่ต้องแยก
const IKEV2_ENCRYPTIONS = [
  { value: "aes-cbc-256", label: "AES-CBC 256-bit (Recommended)" },
  { value: "aes-cbc-192", label: "AES-CBC 192-bit" },
  { value: "aes-cbc-128", label: "AES-CBC 128-bit" },
  { value: "aes-gcm-256", label: "AES-GCM 256-bit" },
  { value: "aes-gcm-128", label: "AES-GCM 128-bit" },
  { value: "en-3des", label: "3DES" },
  { value: "des", label: "DES (Not recommended)" },
];

// (bug 90) AES-GCM เป็น combined-mode cipher มี authentication อยู่ในตัวแล้ว อุปกรณ์ทั้งสอง
// ยี่ห้อห้ามตั้ง integrity คู่กัน (Juniper: "the Authentication Algorithm must not be set" ·
// Cisco: proposal จะถูกมองว่าไม่สมบูรณ์) - backend จัดการให้แล้ว (Cisco เปลี่ยนไปใส่ prf,
// Junos ตัดทิ้ง) แต่ฟอร์มต้องไม่หลอกผู้ใช้ว่าค่านี้มีผล จึงเปลี่ยน label ให้บอกตรง ๆ
const IKEV2_COMBINED_MODE = new Set(["aes-gcm-256", "aes-gcm-128"]);

const IKEV2_INTEGRITIES = [
  { value: "sha256", label: "SHA-256 (Recommended)" },
  { value: "sha384", label: "SHA-384" },
  { value: "sha512", label: "SHA-512" },
  { value: "sha1", label: "SHA-1 (Not recommended)" },
  { value: "md5", label: "MD5 (Not recommended)" },
];

const IKEV2_DH_GROUPS = [
  { value: "fourteen", label: "Group 14 - 2048-bit MODP (Recommended)" },
  { value: "fifteen", label: "Group 15 - 3072-bit MODP" },
  { value: "sixteen", label: "Group 16 - 4096-bit MODP" },
  { value: "nineteen", label: "Group 19 - 256-bit ECP" },
  { value: "twenty", label: "Group 20 - 384-bit ECP" },
  { value: "twenty-one", label: "Group 21 - 521-bit ECP" },
  { value: "twenty-four", label: "Group 24 - 2048-bit (256 subgroup) MODP" },
  { value: "five", label: "Group 5 - 1536-bit MODP (Not recommended)" },
  { value: "two", label: "Group 2 - 1024-bit MODP (Not recommended)" },
  { value: "one", label: "Group 1 - 768-bit MODP (Not recommended)" },
];

// esp ที่เป็น combined-mode (มี integrity ในตัวอยู่แล้ว ไม่ต้องเลือก integrity
// แยก) และ esp ที่ต้องระบุ key size (esp-192-aes/esp-256-aes ล็อคขนาดในชื่อแล้ว
// ไม่ต้องมี key size ให้เลือกซ้ำ) - ตรงกับ `when` constraint ใน YANG
const IPSEC_COMBINED_MODE = new Set(["esp-gcm", "esp-gmac"]);
const IPSEC_NEEDS_KEY_SIZE = new Set(["esp-aes", "esp-gcm", "esp-gmac"]);



// (bug 89) ค่าที่ "อุปกรณ์รุ่นที่ใช้จริงไม่รับ" - ต่างจาก IPSEC_UNSUPPORTED_JUNIPER ข้างบน
// ที่เป็นเรื่องไม่มี algorithm ที่ตรงกันให้ map
//
// ที่มา: ผู้ใช้กด "?" บนอุปกรณ์จริงแล้วส่งรายการมาให้ (6 ก.ย. 2026)
//   vSRX    - security ike proposal / security ipsec proposal / perfect-forward-secrecy
//   C8000v  - crypto ikev2 proposal / crypto ipsec transform-set
//
// **สำคัญ: YANG บอกไม่ได้ว่ารุ่นนี้รองรับอะไร** - junos-es-conf-security.yang เป็น schema
// รวมของ SRX ทั้ง family ตอนไล่ bug 71 เคยตรวจ YANG แล้วสรุปว่า "ค่าที่ map ถูกทุกตัว"
// ซึ่งตรวจถูกแต่สรุปผิด เพราะ vSRX รองรับแค่ subset ของที่ YANG ประกาศ
//
// **เคสที่อันตรายที่สุดคือ group15/16 บน Juniper** - ไม่ error แต่ commit แล้วอุปกรณ์ขึ้น
// "Warning: statement ignored: unsupported platform (vsrx)" คือหน้าเว็บเขียวแต่ค่าไม่ถูกใช้
// ผู้ใช้ไม่มีทางรู้เลย จึงต้องตัดออกจาก dropdown ไม่ใช่ปล่อยให้เลือกแล้วไปตายที่อุปกรณ์
//
// ถ้าวันหนึ่งเปลี่ยนไปใช้อุปกรณ์รุ่นอื่นที่รองรับมากกว่านี้ ให้กด "?" บนรุ่นนั้นแล้วอัปเดต
// ที่นี่ พร้อมแก้ Literal ใน vendor_translators ให้ตรงกัน (คนละที่แต่ต้องตรงกันเสมอ)
const UNSUPPORTED_BY_PLATFORM = {
  juniper: {
    ikev2Integrity: new Set(["sha512"]),
    ikev2Group: new Set(["fifteen", "sixteen", "twenty-one"]),
    ipsecIntegrity: new Set(["esp-sha384-hmac", "esp-sha512-hmac"]),
    pfsGroup: new Set(["group15", "group16", "group21"]),
  },
  cisco: {
    ikev2Encryption: new Set(["en-3des", "des"]),
    ikev2Integrity: new Set(["md5"]),
    ikev2Group: new Set(["one", "two", "five", "twenty-four"]),
    ipsecIntegrity: new Set(["esp-md5-hmac"]),
    pfsGroup: new Set(["group1", "group2", "group5", "group24"]),
  },
};

function supportedOptions(options, vendorKey, field) {
  const blocked = UNSUPPORTED_BY_PLATFORM[vendorKey]?.[field];
  return blocked ? options.filter((option) => !blocked.has(option.value)) : options;
}


const IPSEC_INTEGRITIES = [
  { value: "esp-sha256-hmac", label: "SHA-256 HMAC (Recommended)" },
  { value: "esp-sha384-hmac", label: "SHA-384 HMAC" },
  { value: "esp-sha512-hmac", label: "SHA-512 HMAC" },
  { value: "esp-sha-hmac", label: "SHA-1 HMAC (Not recommended)" },
  { value: "esp-md5-hmac", label: "MD5 HMAC (Not recommended)" },
];


// (bug 95) ยุบ "ตัวเลือก AES + ช่อง Key Size" ให้เหลือ dropdown เดียว
//
// เดิมผู้ใช้ต้องเลือก "AES (แนะนำ)" แล้วไปกรอก Key Size อีกช่อง ทั้งที่ผลลัพธ์ซ้ำกับ
// ตัวเลือก AES-256 / AES-192 ที่อยู่ในลิสต์เดียวกันอยู่แล้ว - คำพูดผู้ใช้: "ค่ามันซ้ำ
// แล้วต้องกรอกหลายช่อง ทำไมต้องทำด้วยอ่ะ ยุบเอาก็ได้นิ"
//
// ตรงนี้เก็บ mapping ไว้ว่าตัวเลือกที่ผู้ใช้เห็น 1 ตัว = (encryption, keySize) อะไร
// backend ยังรับ 2 พารามิเตอร์เหมือนเดิม (Cisco ต้องมี key-bit จริง ๆ สำหรับ esp-aes/
// esp-gcm ตาม YANG) แค่ไม่ให้ผู้ใช้ต้องรับรู้
const IPSEC_ALGORITHMS = [
  { value: "aes-256-cbc", label: "AES-CBC 256-bit (Recommended)", encryption: "esp-256-aes" },
  { value: "aes-192-cbc", label: "AES-CBC 192-bit", encryption: "esp-192-aes" },
  { value: "aes-128-cbc", label: "AES-CBC 128-bit", encryption: "esp-aes", keySize: "128" },
  { value: "aes-256-gcm", label: "AES-GCM 256-bit", encryption: "esp-gcm", keySize: "256" },
  { value: "aes-192-gcm", label: "AES-GCM 192-bit", encryption: "esp-gcm", keySize: "192" },
  { value: "aes-128-gcm", label: "AES-GCM 128-bit", encryption: "esp-gcm", keySize: "128" },
  { value: "esp-seal", label: "SEAL 160-bit", encryption: "esp-seal" },
  { value: "3des-cbc", label: "3DES", encryption: "esp-3des" },
  { value: "des-cbc", label: "DES (Not recommended)", encryption: "esp-des" },
];

// ตัวเลือกที่แต่ละยี่ห้อไม่รับ (bug 89) - อ้างอิงชุดเดิม แค่แปลงเป็นชื่อตัวเลือกใหม่
// (bug 89) ตัวเลือก encryption ของ IPsec ย้ายมากรองที่นี่แทน UNSUPPORTED_BY_PLATFORM
// เพราะ bug 95 ยุบ encryption+keySize เป็นตัวเลือกเดียวแล้ว ชื่อค่าจึงคนละชุดกัน
const IPSEC_ALGO_UNSUPPORTED = {
  juniper: new Set(["esp-seal"]),                              // ไม่มี algorithm ที่ตรงกันใน Junos
  cisco: new Set(["3des-cbc", "des-cbc", "aes-192-gcm"]),      // C8000v ไม่รับ
};

// แปลงค่าที่อ่านจากอุปกรณ์กลับเป็นตัวเลือกเดียวของฟอร์ม (bug 92 + 95)
function toIpsecAlgorithm(encryption, keySize) {
  if (!encryption) return null;
  // IOS XE บางรุ่นตอบ AES-CBC แบบ generic + key-bit แยก แม้ความหมายจะเท่ากับ
  // leaf แบบระบุขนาดในชื่อ (`esp-aes` + 256 == `esp-256-aes`) ให้รวมเป็นรูป
  // canonical ก่อนหา option เพื่อให้ตารางและ Edit form เลือก AES-256 ได้ถูกต้อง
  // แทนที่จะมองว่าเป็นค่าที่อ่านไม่ได้
  const sizedAes = encryption === "esp-aes" && ["192", "256"].includes(String(keySize || ""));
  const normalizedEncryption = sizedAes ? `esp-${keySize}-aes` : encryption;
  const normalizedKeySize = sizedAes ? null : (keySize || null);
  const direct = IPSEC_ALGORITHMS.find(
    (a) => a.encryption === normalizedEncryption && (a.keySize || null) === normalizedKeySize,
  );
  if (direct) return direct.value;
  // (เคส E) Cisco ไม่เขียน key-bit ลง config เมื่อใช้ขนาด key ค่าเริ่มต้น - `crypto ipsec
  // transform-set X esp-aes esp-sha256-hmac` (ไม่มีเลขต่อท้าย) คือ AES-**128** และ reply
  // ก็ไม่มี <key-bit> กลับมาด้วย เดิมจึงจับคู่ไม่ติดแล้วคืน null ทำให้ buildInitialValues
  // ตกไปใช้ชุด recommend = AES-256 **แล้วเพราะค่าที่ได้บังเอิญเท่ากับชุด recommend พอดี
  // ฟอร์มจึงเด้งไปโหมด System Recommend ที่ไม่มี dropdown ให้เห็นค่าด้วยซ้ำ** ผู้ใช้ที่
  // เข้ามาแก้แค่ Peer IP กด Save = อัป encryption ของจริงจาก 128 เป็น 256 โดยไม่รู้ตัว
  // (transform-set ถูกเขียนด้วย nc:operation="replace" ทุกครั้ง)
  //
  // เติมค่าเริ่มต้นของอุปกรณ์ให้ตรงนี้แทนการเดาที่ปลายทาง - ผลตอน Save คือ config
  // เปลี่ยนจาก `esp-aes` เป็น `esp-aes 128` ซึ่งเป็น algorithm เดิมทุกประการ แค่เขียน
  // ขนาด key ชัดเจนขึ้น ต่างจากเดิมที่เปลี่ยนความแรงของ cipher จริง ๆ
  if (!keySize) {
    const defaulted = IPSEC_ALGORITHMS.find((a) => a.encryption === encryption && a.keySize === "128");
    if (defaulted) return defaulted.value;
  }
  // Junos คืนชื่อ algorithm ตรง ๆ อยู่แล้ว (aes-256-cbc ฯลฯ)
  return IPSEC_ALGORITHMS.some((a) => a.value === encryption) ? encryption : null;
}

const PFS_DH_GROUPS = [
  { value: "group14", label: "Group 14 - 2048-bit MODP (Recommended)" },
  { value: "group15", label: "Group 15 - 3072-bit MODP" },
  { value: "group16", label: "Group 16 - 4096-bit MODP" },
  { value: "group19", label: "Group 19 - 256-bit ECP" },
  { value: "group20", label: "Group 20 - 384-bit ECP" },
  { value: "group21", label: "Group 21 - 521-bit ECP" },
  { value: "group24", label: "Group 24 - 2048-bit (256 subgroup) MODP" },
  { value: "group5", label: "Group 5 - 1536-bit MODP (Not recommended)" },
  { value: "group2", label: "Group 2 - 1024-bit MODP (Not recommended)" },
  { value: "group1", label: "Group 1 - 768-bit MODP (Not recommended)" },
];

// ค่าที่ใช้ตอนเลือก "System Recommend" (ไม่ให้ผู้ใช้เห็น dropdown เลย) - เป็นชุด
// ที่ปลอดภัย/ใช้กันแพร่หลาย (AES-256 + SHA-256 + Group 14) ไม่ใช่ค่าที่แปลกใหม่
// เกินไปจนอุปกรณ์ปลายทางอื่นอาจไม่รองรับ
const IKEV2_RECOMMENDED = { encryption: "aes-cbc-256", integrity: "sha256", group: "fourteen" };
// ข้อความเดียวใช้ทั้ง 2 ยี่ห้อ: บังคับตอนสร้างใหม่ และเมื่อผู้ใช้เลือก Change Key ใน Edit
const PSK_REQUIRED_MESSAGE = "Please enter Pre-Shared Key";
// (bug 95) เก็บเป็น "ชื่อ algorithm ตัวเดียว" แล้ว ไม่ใช่ encryption + keySize แยกกัน
const IPSEC_RECOMMENDED = { algorithm: "aes-256-cbc", integrity: "esp-sha256-hmac" };

// ตัวเลือก/ตัวช่วยที่โมดูล brownfield ต้องใช้ - รวม recommended set เพื่อให้ Edit
// pre-fill ปุ่ม System Recommend/Specific จากค่าจริงได้เหมือน managed profile
const BROWNFIELD_CATALOG = {
  toIpsecAlgorithm, IPSEC_ALGORITHMS, IPSEC_COMBINED_MODE,
  IKEV2_RECOMMENDED, IPSEC_RECOMMENDED,
};

// โหมด Edit: pre-fill ด้วย "ค่าจริงบนอุปกรณ์" (bug 92)
//
// เดิมฟอร์มแก้ไขไม่ยอม pre-fill ชั้น IKEv2 เลย เพราะ get_security_profile_information
// ไม่ได้ดึง ikev2/proposal (Cisco) กับ ike/proposal (Juniper) มา และฝั่ง Juniper
// ยัง pre-fill ชั้น IPsec ไม่ได้อีก เพราะ parser คืนชื่อ Junos-native
// ("aes-256-cbc", "hmac-sha-256-128") ที่ไม่ตรง enum ที่ create_security_profile
// ต้องการ ("esp-256-aes", "esp-sha256-hmac") ส่งไปตรง ๆ โดน pydantic ปฏิเสธ
//
// ผลคือฟอร์มถอยไปตั้ง "System Recommend" ให้เอง ซึ่งอันตรายกว่าที่คิด: ผู้ใช้ที่
// ตั้งใจเข้ามาแก้แค่ Peer IP หรือแค่ฝั่ง IPsec กด Save แล้ว **ค่า IKEv2 ที่ตั้งไว้
// ถูกเขียนทับด้วย default ทั้งชุด** โดยไม่มีอะไรเตือน - หน้าจอบอกอย่าง อุปกรณ์เป็นอีกอย่าง
//
// ทางแก้: ดึง proposal/policy มาจริง (แก้ที่ get_security_profile_information)
// แล้ว map ชื่อ Junos กลับเป็น enum ของฟอร์มใน parser (JUNOS_TO_FORM) - parser
// ส่งมาให้ที่ editTarget.form พร้อมใช้ ที่นี่แค่หยิบมาใส่ ถ้าช่องไหนอ่านไม่ได้จริง ๆ
// ค่อยตกไปใช้ recommend เฉพาะช่องนั้น
//
// mode (recommend/custom) คำนวณจากการเทียบค่าจริงกับชุด recommend ไม่ใช่ hardcode
// ตาม vendor แบบเดิม (Juniper=recommend เสมอ / Cisco=custom เสมอ) ซึ่งทำให้
// ฝั่งหนึ่งซ่อนค่าจริงไว้หลังปุ่ม recommend
//
// PSK ยังไม่มีทาง pre-fill (อุปกรณ์ไม่คืนค่ากลับมา) - ช่องนี้ช่องเดียวที่ยังว่างเสมอ
//
// (เคส C) wanInterface ของ Juniper pre-fill ได้แล้วจาก external-interface ที่ parser
// อ่านมาจาก gateway ตัวจริง - เดิมปล่อยว่างแล้วให้ useEffect เดาค่าจาก zone WAN ให้
// ซึ่งเป็นบั๊กแบบเดียวกับชั้น IKEv2 ข้างบนเป๊ะ ๆ: ผู้ใช้ที่เข้ามาแก้แค่ค่าอื่นกด Save แล้ว
// gateway ถูกย้ายไปผูกกับขาที่ระบบเดาให้ (create_security_profile เขียน gateway ด้วย
// replace ทุกครั้ง) โดยหน้าจอไม่เคยบอกว่าของจริงคือขาไหน
function buildInitialValues(mode, editTarget) {
  if (mode !== "edit" || !editTarget) {
    return {
      name: "",
      peerIp: "",
      psk: "",
      wanInterface: "",
      ikev2Mode: "recommend",
      ikev2Encryption: IKEV2_RECOMMENDED.encryption,
      ikev2Integrity: IKEV2_RECOMMENDED.integrity,
      ikev2Group: IKEV2_RECOMMENDED.group,
      ipsecMode: "recommend",
      ipsecAlgorithm: IPSEC_RECOMMENDED.algorithm,
      ipsecIntegrity: IPSEC_RECOMMENDED.integrity,
      enablePfs: false,
      pfsGroup: "group14",
      tunnelMode: "tunnel",
    };
  }
  // (bug 92) pre-fill ด้วย "ค่าจริงบนอุปกรณ์" ไม่ใช่ค่า default ของระบบ
  //
  // parser คืน editTarget.form มาให้แล้วในรูป enum ของฟอร์ม (แปลงชื่อ Junos-native
  // กลับมาแล้ว) ถ้าอ่านค่าไหนไม่ได้ค่อยตกไปใช้ recommend เฉพาะค่านั้น
  //
  // และตั้ง mode เป็น custom เมื่อค่าจริงต่างจาก recommend - เดิม Juniper ตั้ง recommend
  // เสมอส่วน Cisco ตั้ง custom เสมอ ทำให้หมวดหนึ่งซ่อนค่าจริงอีกหมวดโชว์ ผู้ใช้สับสน
  // และที่แย่กว่านั้นคือกด Save แล้วค่า IKEv2 ที่ตั้งไว้ถูกเขียนทับด้วย default
  const form = editTarget.form || {};
  const hasPfs = !!(form.pfsGroup || editTarget.pfsGroupRaw);
  const pfsGroup = form.pfsGroup || editTarget.pfsGroupRaw || "group14";

  const ikev2 = {
    encryption: form.ikev2Encryption || IKEV2_RECOMMENDED.encryption,
    integrity: form.ikev2Integrity || IKEV2_RECOMMENDED.integrity,
    group: form.ikev2Group || IKEV2_RECOMMENDED.group,
  };
  const ikev2IsRecommend =
    ikev2.encryption === IKEV2_RECOMMENDED.encryption &&
    ikev2.integrity === IKEV2_RECOMMENDED.integrity &&
    ikev2.group === IKEV2_RECOMMENDED.group;

  const resolvedIpsecAlgorithm = toIpsecAlgorithm(form.ipsecEncryption, form.ipsecKeySize);
  const ipsecAlgorithm = resolvedIpsecAlgorithm || IPSEC_RECOMMENDED.algorithm;
  const ipsecIntegrity = form.ipsecIntegrity || IPSEC_RECOMMENDED.integrity;
  // (เคส E) ยืนยันด้วยว่า "อ่านค่าจริงจากอุปกรณ์ได้" ก่อนจะยอมพับไว้หลังปุ่ม System
  // Recommend - ถ้าอ่านไม่ออกแล้วยังเด้งเป็น recommend ผู้ใช้จะไม่เห็นเลยว่ากด Save แล้ว
  // ระบบจะเขียนอะไรลงอุปกรณ์ (โหมด recommend ไม่มี dropdown ให้ดู) เปิด custom ไว้ให้
  // ค่าที่จะถูกส่งโผล่บนหน้าจอเสมอ ตามหลักเดียวกับที่ bug 92 ใช้กับชั้น IKEv2
  const ipsecIsRecommend =
    Boolean(resolvedIpsecAlgorithm) &&
    ipsecAlgorithm === IPSEC_RECOMMENDED.algorithm &&
    ipsecIntegrity === IPSEC_RECOMMENDED.integrity;

  return {
    name: editTarget.name || "",
    peerIp: editTarget.peerIp || "",
    psk: "",
    wanInterface: editTarget.wanInterface || "",
    ikev2Mode: ikev2IsRecommend ? "recommend" : "custom",
    ikev2Encryption: ikev2.encryption,
    ikev2Integrity: ikev2.integrity,
    ikev2Group: ikev2.group,
    ipsecMode: ipsecIsRecommend ? "recommend" : "custom",
    ipsecAlgorithm,
    ipsecIntegrity,
    enablePfs: hasPfs,
    pfsGroup,
    tunnelMode: editTarget.modeRaw === "transport" ? "transport" : "tunnel",
  };
}

// สร้าง IKEv2 proposal/policy/keyring/profile + IPsec transform-set/profile
// (Cisco) หรือ ike/proposal+policy+gateway + ipsec/proposal+policy (Juniper)
// ทั้งชุดในคำสั่งเดียว (create_security_profile) - ผู้ใช้กรอกแค่ชื่อ/peer IP/PSK/
// เลือก algorithm (หรือปล่อย System Recommend) ที่เหลือ backend ตั้งชื่อ object
// ย่อยให้เองทั้งหมดจาก `name` - Juniper ต้องมี WAN Interface เพิ่ม (ยืนยันจริง
// ว่า Junos ปฏิเสธ commit ทันทีถ้า IKE gateway ไม่มี external-interface แม้ YANG
// จะไม่บังคับก็ตาม - "The IKE gateway X must configure the external-interface")
// และไม่รองรับ transport mode (Junos route-based VPN ผ่าน st0 เป็น tunnel mode
// เสมอ) - ซ่อน field ที่ไม่เกี่ยวไปเลยแทนที่จะให้เลือกแล้วเจอ error ที่รู้
// ล่วงหน้าอยู่แล้วว่าจะพัง
export default function SecurityProfileFormModal({ devId, vendor, mode = "create", editTarget = null, onClose, onSaved }) {
  const isJuniper = vendor === "juniper";
  const isEdit = mode === "edit" && !!editTarget;
  // **ชื่อ Security Profile ที่สร้างแล้ว ห้ามเปลี่ยนทุกกรณี ทุกยี่ห้อ** (ผู้ใช้ตัดสินใจ
  // 20 ก.ย. 2026) - เดิมล็อกเฉพาะตอนมี tunnel ผูกอยู่ (bug 67) หรือตอนที่ยังตอบไม่ได้ว่ามี
  // ผูกอยู่ไหม แต่การเปลี่ยนชื่อไม่เคยเป็นการ "แก้ค่า" เลยตั้งแต่แรก: ชื่อ object ทุกตัวบน
  // อุปกรณ์ derive จากชื่อ profile (`-IKEV2-PROP`/`-KEYRING`/`-GATEWAY`/…) การเปลี่ยนชื่อ
  // จึงเท่ากับสร้างชุดใหม่ทั้งชุดแล้วรื้อของเก่าทิ้งในคำสั่งเดียว ซึ่งพ่วงผลข้างเคียงมาเสมอ
  // (PSK ต้องตั้งใหม่เพราะคัดลอกของเก่ามาไม่ได้ · อะไรที่อ้างชื่อเก่าอยู่จะชี้ไปที่ของที่
  // ไม่มีแล้ว) ถ้าต้องการชื่อใหม่จริง ๆ ให้สร้าง profile ใหม่แล้วลบตัวเก่า ซึ่งเห็นผล
  // แต่ละก้าวชัดกว่าและกู้กลับง่ายกว่า
  const nameLocked = isEdit;
  // profile ที่มีอยู่บนอุปกรณ์อยู่ก่อน (ไม่ได้สร้างจากระบบ) - แก้ในที่เดิมด้วยชื่อ object จริง ส่งเฉพาะ field ที่
  // เปลี่ยน ไม่เขียนทับ (ดู securityProfileBrownfield.js) ส่วนที่ระบบสร้างเองใช้เส้นทางเดิมที่ตรวจบนอุปกรณ์แล้ว
  const isBrownfield = isEdit && !editTarget.managed && Boolean(editTarget.real);
  const real = isBrownfield ? editTarget.real : null;
  const [initialValues] = useState(() =>
    isBrownfield ? buildBrownfieldInitialValues(editTarget, BROWNFIELD_CATALOG) : buildInitialValues(mode, editTarget),
  );
  const [values, setValues] = useState(initialValues);
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  // อุปกรณ์ไม่คืน PSK เดิมกลับมา จึงเริ่ม Edit ด้วยการคง key เดิมเสมอ ผู้ใช้ต้อง
  // เลือก Change Key อย่างชัดเจนก่อนจึงจะแสดงช่องและส่งค่าใหม่ไปยังอุปกรณ์
  const [pskMode, setPskMode] = useState(isEdit ? "existing" : "change");

  const { data: ifBriefData, loading: ifBriefLoading } = getDeviceInformation(
    devId,
    isJuniper ? "get_ip_interface_brief" : null
  );
  const briefInterfaces = ifBriefData?.normalized
    ? ifBriefData.result.map((row) => row.name).filter((name) => isJuniperSelectableInterfaceUnit(name))
    : [];
  // (เคส C) ค่าที่อุปกรณ์ผูกไว้จริงต้องมีใน dropdown เสมอ ไม่งั้น <select> ที่ value ไม่ตรง
  // กับ <option> ตัวไหนเลยจะแสดงเป็นช่องว่าง ทั้งที่ state ถืออยู่ = จอไม่ตรงกับอุปกรณ์อีกแบบ
  // (เช่น interface ที่ไม่มี IPv4 จึงไม่โผล่ใน get_ip_interface_brief)
  const interfaceOptions =
    isJuniperSelectableInterfaceUnit(values.wanInterface) && !briefInterfaces.includes(values.wanInterface)
      ? [values.wanInterface, ...briefInterfaces]
      : briefInterfaces;

  function setField(name, value) {
    setValues((prev) => ({ ...prev, [name]: value }));
  }

  // user ขอ: default "WAN Interface" เป็น interface ที่เป็นสมาชิกของ zone "WAN"
  // ให้เองก่อนเลย (IKE gateway แทบทุกเคสจริงผูกกับ WAN interface อยู่แล้ว) -
  // (เคส C) ตอนนี้โหมดแก้ไข pre-fill ด้วยค่าจริงจากอุปกรณ์แล้ว เงื่อนไข "ยังไม่มีค่า"
  // จึงกลายเป็นตัวกันการเดาทับค่าจริงไปในตัว (เดาให้เฉพาะตอนสร้างใหม่ หรือตอนที่
  // อุปกรณ์ไม่มี external-interface ให้อ่านจริง ๆ) - ห้ามเปลี่ยนเป็นเดาทุกครั้ง
  const { data: zoneData } = getDeviceInformation(devId, isJuniper ? "get_security_zone_information" : null);
  const wanZoneInterfaces = getWanZoneInterfaces({ vendor, zoneResult: zoneData });
  useEffect(() => {
    if (!isJuniper || values.wanInterface) return;
    const match = wanZoneInterfaces.find((name) => interfaceOptions.includes(name));
    if (match) setField("wanInterface", match);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isJuniper, values.wanInterface, wanZoneInterfaces.join(","), interfaceOptions.join(",")]);

  // (bug 89) กรองตัวเลือกให้เหลือเฉพาะที่อุปกรณ์รุ่นที่ใช้จริงรับได้
  const vendorKey = isJuniper ? "juniper" : "cisco";
  // (bug 95) dropdown เดียว - ไม่มีช่อง Key Size แยกอีกแล้ว
  const ipsecAlgorithmOptions = IPSEC_ALGORITHMS.filter(
    (option) => !IPSEC_ALGO_UNSUPPORTED[vendorKey]?.has(option.value),
  );
  const ikev2EncryptionOptions = supportedOptions(IKEV2_ENCRYPTIONS, vendorKey, "ikev2Encryption");
  const ikev2IntegrityOptions = supportedOptions(IKEV2_INTEGRITIES, vendorKey, "ikev2Integrity");
  const ikev2GroupOptions = supportedOptions(IKEV2_DH_GROUPS, vendorKey, "ikev2Group");
  const ipsecIntegrityOptions = supportedOptions(IPSEC_INTEGRITIES, vendorKey, "ipsecIntegrity");
  const pfsGroupOptions = supportedOptions(PFS_DH_GROUPS, vendorKey, "pfsGroup");
  const selectedIpsecAlgo =
    IPSEC_ALGORITHMS.find((a) => a.value === values.ipsecAlgorithm) || IPSEC_ALGORITHMS[0];
  const ipsecCombinedMode = IPSEC_COMBINED_MODE.has(selectedIpsecAlgo.encryption);
  // (bug 90) เลือก GCM แล้ว integrity จะไม่ถูกใช้เป็น integrity อีกต่อไป
  const ikev2IsCombinedMode = IKEV2_COMBINED_MODE.has(values.ikev2Encryption);

  // Brownfield ที่ PSK object ใช้ร่วมกับ profile อื่นยังต้องห้ามเปลี่ยน เพื่อไม่ให้การ
  // แก้ profile นี้เปลี่ยน key ของ profile อื่นไปพร้อมกันโดยไม่ตั้งใจ
  const pskChangeBlocked = isBrownfield && !real.sections.psk.editable;
  const pskRequired = !isEdit || pskMode === "change";

  function selectPskMode(nextMode) {
    if (nextMode === "change" && pskChangeBlocked) return;
    setPskMode(nextMode);
    if (nextMode === "existing") setField("psk", "");
  }

  // brownfield: เหตุผลที่ส่วนนั้นแก้ไม่ได้ (ว่าง = แก้ได้) - ส่วนที่แก้ไม่ได้ยังแสดงค่าจริง แค่ disabled
  const sectionReason = (section) => (isBrownfield && !real.sections[section]?.editable ? real.sections[section].reason : "");
  const peerReason = sectionReason("peer");
  const ikev2Reason = sectionReason("ikev2");
  const ipsecReason = sectionReason("ipsec");
  const pfsReason = sectionReason("pfs");
  const noIkev2Values = isBrownfield && real.raw.ikev2Encryption.length === 0 && real.raw.ikev2Group.length === 0;
  const noIpsecValues = isBrownfield && !real.raw.ipsecEncryption;
  // ค่าจริงอยู่นอกตัวเลือกที่กรองตามรุ่น หรือมีหลายค่า -> เติม option "ค่าปัจจุบัน" ไม่งั้น select จะโชว์ว่าง
  const shown = (options, current, rawList) => (isBrownfield ? withCurrentOption(options, current, rawList) : options);
  const ipsecRawLabel = isBrownfield && real.raw.ipsecEncryption
    ? [real.raw.ipsecKeySize ? `${real.raw.ipsecEncryption} ${real.raw.ipsecKeySize}` : real.raw.ipsecEncryption]
    : [];

  function buildCommonParams() {
    const name = values.name.trim();
    // ด่านที่สอง - ถึงช่องจะ disabled แล้วก็กันไว้อีกชั้นเผื่อ state เพี้ยน
    if (nameLocked && name !== editTarget.name) {
      throw new Error("Cannot rename an existing Security Profile - to change name, create a new Profile and delete the old one");
    }
    // Peer IP ผ่านตัวตรวจกลางตัวเดียวกับ NAT/Static Route (utils/ipv4Input) แทนการ
    // เช็คแค่ "ไม่ว่าง" แบบเดิม - translator ตรวจด้วย validate_ipv4() อยู่แล้ว แต่การ
    // ปล่อยค่าผิดรูปแบบวิ่งไปถึง backend ได้แปลว่าผู้ใช้ต้องรอ round-trip เพื่อเห็นว่า
    // พิมพ์ผิด และข้อความที่ได้กลับมาเป็นภาษาของ pydantic ไม่ใช่ภาษาของฟอร์ม
    // ใช้ค่า .value ที่ผ่านการ normalize แล้วส่งต่อ (ตัดช่องว่างหัวท้ายให้ในตัว)
    const peerIp = validateIPv4Input(values.peerIp, { mode: "address" });
    // Existing Key ต้องไม่ส่ง field นี้เด็ดขาด เพราะค่าเดิมอ่านกลับมาไม่ได้ การส่งค่าว่าง
    // หรือค่าค้างใน state อาจล้าง/เปลี่ยน secret บนอุปกรณ์โดยผู้ใช้ไม่ได้ตั้งใจ
    const psk = !isEdit || pskMode === "change" ? values.psk : "";

    const ikev2 =
      values.ikev2Mode === "recommend"
        ? IKEV2_RECOMMENDED
        : { encryption: values.ikev2Encryption, integrity: values.ikev2Integrity, group: values.ikev2Group };

    // (bug 95) ผู้ใช้เลือก algorithm ตัวเดียว - แปลงกลับเป็น encryption + keySize ให้ backend
    const chosen =
      values.ipsecMode === "recommend" ? IPSEC_RECOMMENDED.algorithm : values.ipsecAlgorithm;
    const algo = IPSEC_ALGORITHMS.find((a) => a.value === chosen) || IPSEC_ALGORITHMS[0];
    const ipsec = {
      encryption: algo.encryption,
      keySize: algo.keySize || null,
      integrity:
        values.ipsecMode === "recommend" ? IPSEC_RECOMMENDED.integrity : values.ipsecIntegrity,
    };
    const needsKeySize = IPSEC_NEEDS_KEY_SIZE.has(ipsec.encryption);
    const combinedMode = IPSEC_COMBINED_MODE.has(ipsec.encryption);

    const params = {
      name,
      peer_ip: peerIp.value,
      ikev2_encryption: ikev2.encryption,
      ikev2_integrity: ikev2.integrity,
      ikev2_group: ikev2.group,
      ipsec_encryption: ipsec.encryption,
    };
    if (!combinedMode) params.ipsec_integrity = ipsec.integrity;
    if (needsKeySize) params.ipsec_key_size = ipsec.keySize;
    if (values.enablePfs) params.pfs_group = values.pfsGroup;
    // (bug 93) ส่ง psk เฉพาะตอนที่ผู้ใช้กรอกจริง - ไม่ส่ง = translator ไม่แตะ object ที่
    // เก็บ PSK อยู่ (keyring ของ Cisco / ike policy ของ Juniper) ค่าเดิมบนอุปกรณ์จึงรอด
    if (psk) params.psk = psk;
    return { name, peerIp, psk, params };
  }

  async function handleSubmitCisco(event) {
    event.preventDefault();
    setError("");

    const { name, peerIp, psk, params } = buildCommonParams();
    if (!name) return setError("Please enter Security Profile name");
    if (!peerIp.valid) return setError("Please enter a valid Peer IP, e.g. 203.0.113.5");
    if (pskRequired && !psk) return setError(PSK_REQUIRED_MESSAGE);
    delete params.ikev2_encryption;
    delete params.ikev2_integrity;
    delete params.ikev2_group;
    params.tunnel_mode = values.tunnelMode;

    setSubmitting(true);
    try {
      // (ปัญหาที่ 2 ขั้น B0) ตรวจค่าที่จะใช้สร้างใหม่ให้ผ่านก่อน "แล้วค่อยเริ่มลบ"
      // ไม่งั้นถ้าค่าผิด (เช่น peer_ip ผิดรูปแบบ - เข้มขึ้นตั้งแต่แก้ BUG-15) จะรื้อ
      // 6 object ของ VPN ที่ใช้งานอยู่สำเร็จไปแล้วก่อนจะมาโดนปฏิเสธที่ขั้นสร้าง
      // = tunnel ล่มโดยไม่มีอะไรมาแทน และไม่มีปุ่มไหนกู้กลับได้
      // (ระลอก C1) เดิมตอนแก้ไขต้องยิง 7 RPC แยกกัน (รื้อ 6 object แล้วค่อยสร้างใหม่)
      // ซึ่งถ้าขั้นสร้างพัง VPN ที่ใช้งานอยู่จะถูกรื้อทิ้งหมดโดยไม่มีอะไรมาแทน - ตอนนี้
      // create_security_profile ใช้ nc:operation="replace" ทั้ง 6 object แล้ว จึงไม่ต้อง
      // ลบอะไรก่อนเลย อุปกรณ์แทนที่ให้ในก้าวเดียว **1 action = 1 RPC = ประวัติ 1 แถว**
      //
      // ไม่มี replace_name แล้ว - ชื่อล็อกตายตัวตอนแก้ไข (ดู nameLocked) ชื่อที่ส่งไปจึง
      // เท่ากับชื่อเดิมเสมอ translator ฝั่ง backend ยังรับพารามิเตอร์นี้ได้อยู่ แต่ไม่มี
      // ทางเดินไหนบนหน้าเว็บส่งมันอีกแล้ว
      await validateDeviceCommand(devId, "create_security_profile", params);
      await runDeviceCommand(devId, "create_security_profile", params);
      onSaved();
    } catch (err) {
      setError(err.detail || (isEdit ? "Failed to edit Security Profile" : "Failed to create Security Profile"));
    } finally {
      setSubmitting(false);
    }
  }

  async function handleSubmitJuniper(event) {
    event.preventDefault();
    setError("");

    const { name, peerIp, psk, params } = buildCommonParams();
    if (!name) return setError("Please enter Security Profile name");
    if (!peerIp.valid) return setError("Please enter a valid Peer IP, e.g. 203.0.113.5");
    if (pskRequired && !psk) return setError(PSK_REQUIRED_MESSAGE);
    if (!values.wanInterface) return setError("Please select WAN Interface (Junos requires external-interface, cannot create gateway alone)");
    params.wan_interface = values.wanInterface;
    params.tunnel_mode = "tunnel"; // Junos route-based VPN ผ่าน st0 รองรับแค่ tunnel mode เท่านั้น

    setSubmitting(true);
    try {
      // (ปัญหาที่ 2 ขั้น B0) ตรวจให้ผ่านก่อนเริ่มลบ - เหตุผลเดียวกับฝั่ง Cisco ด้านบน
      await validateDeviceCommand(devId, "create_security_profile", params);

      // (ระลอก C3 + bug 93) เดิมตอนแก้ไขต้องยิง 2 RPC คือ remove ทั้งชุดก่อนแล้วค่อย
      // create ใหม่ = 2 commit แยกกัน ซึ่งทำ 2 อย่างพังพร้อมกัน: PSK ถูกลบไปด้วยทุกครั้ง
      // (ผู้ใช้ต้องพิมพ์กลับมาใหม่) และถ้ามี tunnel ผูกอยู่ commit แรกจะล้มเพราะ ipsec vpn
      // อ้าง gateway ที่กำลังถูกลบ - ตอนนี้ create_security_profile ของ Junos ใช้
      // nc:operation="replace" แล้ว จึงเหลือ RPC เดียวเหมือนฝั่ง Cisco **1 action = 1 RPC**
      // (ไม่มี replace_name เหมือนฝั่ง Cisco - ชื่อล็อกตายตัวตอนแก้ไขแล้ว)
      await runDeviceCommand(devId, "create_security_profile", params);
      onSaved();
    } catch (err) {
      setError(err.detail || (isEdit ? "Failed to edit Security Profile" : "Failed to create Security Profile"));
    } finally {
      setSubmitting(false);
    }
  }

  // แก้ profile ที่มีอยู่บนอุปกรณ์: คำสั่งเดียว (modify_security_profile) มีเฉพาะ field ที่เปลี่ยน + ชื่อ object จริง
  async function handleSubmitBrownfield(event) {
    event.preventDefault();
    setError("");

    let submitted = {
      ...values,
      psk: pskMode === "change" ? values.psk : "",
      // Brownfield ใช้ helper แบบส่งเฉพาะค่าที่เปลี่ยน จึงต้องแปลงโหมด System
      // Recommend เป็นค่าจริงก่อนเปรียบเทียบกับค่าจากอุปกรณ์
      ...(values.ipsecMode === "recommend"
        ? { ipsecAlgorithm: IPSEC_RECOMMENDED.algorithm, ipsecIntegrity: IPSEC_RECOMMENDED.integrity }
        : {}),
      ...(isJuniper && values.ikev2Mode === "recommend"
        ? {
            ikev2Encryption: IKEV2_RECOMMENDED.encryption,
            ikev2Integrity: IKEV2_RECOMMENDED.integrity,
            ikev2Group: IKEV2_RECOMMENDED.group,
          }
        : {}),
    };
    if (pskMode === "change" && !submitted.psk) return setError(PSK_REQUIRED_MESSAGE);
    if (values.peerIp !== initialValues.peerIp) {
      const peer = validateIPv4Input(values.peerIp, { mode: "address" });
      if (!peer.valid) return setError("Please enter a valid Peer IP, e.g. 203.0.113.5");
      submitted = { ...submitted, peerIp: peer.value };
    }
    let request;
    try {
      request = buildBrownfieldModifyParams({
        values: submitted, initial: initialValues, editTarget, isJuniper, catalog: BROWNFIELD_CATALOG,
      });
    } catch (err) {
      return setError(err.message);
    }

    setSubmitting(true);
    try {
      await runDeviceCommand(devId, request.command, request.params);
      onSaved();
    } catch (err) {
      setError(err.detail || "Failed to edit Security Profile");
    } finally {
      setSubmitting(false);
    }
  }

  const handleSubmit = isBrownfield ? handleSubmitBrownfield : isJuniper ? handleSubmitJuniper : handleSubmitCisco;

  return (
    <form className="interface-configuration-form" onSubmit={handleSubmit}>
      {isEdit && <div className="command-output-title">Edit: {editTarget.name}</div>}
      {error && <DismissibleError message={error} onDismiss={() => setError("")} />}

      <div className="interface-configuration-form-field">
        <label className="data-label">Security Profile Name</label>
        <input
          type="text"
          placeholder="HQ-BRANCH1"
          value={values.name}
          onChange={(event) => setField("name", event.target.value)}
          disabled={nameLocked}
          required
        />
      </div>

      <div className="interface-configuration-form-field">
        <label className="data-label">Peer IP</label>
        <IPv4Input
          id="security-profile-peer-ip"
          mode="address"
          label="Peer IP"
          value={values.peerIp}
          onChange={(value) => setField("peerIp", value)}
          disabled={Boolean(peerReason)}
          required
        />
      </div>

      {isJuniper && <>
      <div className="interface-configuration-form-field">
        <label className="data-label">IKEv2 Proposal</label>
        <div
          className={`segmented-control${ikev2Reason ? " locked-choice" : ""}`}
          title={ikev2Reason || undefined}
        >
          <input
            type="radio"
            id="ikev2-recommend"
            name="ikev2-mode"
            value="recommend"
            checked={values.ikev2Mode === "recommend"}
            disabled={Boolean(ikev2Reason)}
            onChange={(event) => setField("ikev2Mode", event.target.value)}
          />
          <label htmlFor="ikev2-recommend">System Recommend</label>
          <input
            type="radio"
            id="ikev2-custom"
            name="ikev2-mode"
            value="custom"
            checked={values.ikev2Mode === "custom"}
            disabled={Boolean(ikev2Reason)}
            onChange={(event) => setField("ikev2Mode", event.target.value)}
          />
          <label htmlFor="ikev2-custom">Specific</label>
        </div>
      </div>

      {values.ikev2Mode === "custom" && !noIkev2Values && (
        <>
          <div className="interface-configuration-form-field">
            <label className="data-label">Encryption</label>
            <select value={values.ikev2Encryption} disabled={Boolean(ikev2Reason)} onChange={(event) => setField("ikev2Encryption", event.target.value)}>
              {shown(ikev2EncryptionOptions, values.ikev2Encryption, real?.raw.ikev2Encryption).map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </div>
          <div className="interface-configuration-form-field">
            <label className="data-label">{ikev2IsCombinedMode ? "PRF" : "Integrity"}</label>
            <select value={values.ikev2Integrity} disabled={Boolean(ikev2Reason)} onChange={(event) => setField("ikev2Integrity", event.target.value)}>
              {shown(ikev2IntegrityOptions, values.ikev2Integrity, real?.raw.ikev2Integrity).map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </div>
          <div className="interface-configuration-form-field">
            <label className="data-label">DH Group</label>
            <select value={values.ikev2Group} disabled={Boolean(ikev2Reason)} onChange={(event) => setField("ikev2Group", event.target.value)}>
              {shown(ikev2GroupOptions, values.ikev2Group, real?.raw.ikev2Group).map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </div>
        </>
      )}
      </>}

      {isEdit && (
        <div className="interface-configuration-form-field">
          <label className="data-label">Pre-Shared Key (PSK)</label>
          <div
            className={`segmented-control${pskChangeBlocked ? " locked-choice" : ""}`}
            title={pskChangeBlocked ? real.sections.psk.reason : undefined}
          >
            <input
              type="radio"
              id="psk-existing"
              name="psk-mode"
              value="existing"
              checked={pskMode === "existing"}
              onChange={() => selectPskMode("existing")}
            />
            <label htmlFor="psk-existing">Using Existing Key</label>
            <input
              type="radio"
              id="psk-change"
              name="psk-mode"
              value="change"
              checked={pskMode === "change"}
              disabled={pskChangeBlocked}
              onChange={() => selectPskMode("change")}
            />
            <label htmlFor="psk-change">Change Key</label>
          </div>
        </div>
      )}

      {(!isEdit || pskMode === "change") && (
        <div className="interface-configuration-form-field">
          <label className="data-label">{isEdit ? "New Pre-Shared Key" : "Pre-Shared Key (PSK)"}</label>
          <input
            type="password"
            value={values.psk}
            onChange={(event) => setField("psk", event.target.value)}
            placeholder="Enter a new Pre-Shared Key"
            required={pskRequired}
          />
        </div>
      )}

      <div className="interface-configuration-form-field">
        <label className="data-label">IPsec Proposal</label>
        <div
          className={`segmented-control${ipsecReason ? " locked-choice" : ""}`}
          title={ipsecReason || undefined}
        >
          <input
            type="radio"
            id="ipsec-recommend"
            name="ipsec-mode"
            value="recommend"
            checked={values.ipsecMode === "recommend"}
            disabled={Boolean(ipsecReason)}
            onChange={(event) => setField("ipsecMode", event.target.value)}
          />
          <label htmlFor="ipsec-recommend">System Recommend</label>
          <input
            type="radio"
            id="ipsec-custom"
            name="ipsec-mode"
            value="custom"
            checked={values.ipsecMode === "custom"}
            disabled={Boolean(ipsecReason)}
            onChange={(event) => setField("ipsecMode", event.target.value)}
          />
          <label htmlFor="ipsec-custom">Specific</label>
        </div>
      </div>

      {values.ipsecMode === "custom" && !noIpsecValues && (
        <>
          <div className="interface-configuration-form-field">
            <label className="data-label">Encryption</label>
            <select value={values.ipsecAlgorithm} disabled={Boolean(ipsecReason)} onChange={(event) => setField("ipsecAlgorithm", event.target.value)} >
              {shown(ipsecAlgorithmOptions, values.ipsecAlgorithm, ipsecRawLabel).map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </div>

          {!ipsecCombinedMode && (
            <div className="interface-configuration-form-field">
              <label className="data-label">Integrity</label>
              <select value={values.ipsecIntegrity} disabled={Boolean(ipsecReason)} onChange={(event) => setField("ipsecIntegrity", event.target.value)} >
                {shown(ipsecIntegrityOptions, values.ipsecIntegrity, real ? [real.raw.ipsecIntegrity] : []).map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </div>
          )}
        </>
      )}

      <div className="interface-configuration-form-field">
        <label className="data-label">IPSec DH Group</label>
        <div className="toggle-switch-container">
          <input
            type="checkbox"
            id="enable-pfs"
            checked={values.enablePfs}
            disabled={Boolean(pfsReason)}
            onChange={(event) => setField("enablePfs", event.target.checked)}
          />
          <label className="toggleSwitch" htmlFor="enable-pfs"></label>
        </div>
      </div>

      {values.enablePfs && (
        <div className="interface-configuration-form-field">
          <label className="data-label">PFS DH Group</label>
          <select value={values.pfsGroup} disabled={Boolean(pfsReason)} onChange={(event) => setField("pfsGroup", event.target.value)} >
            {shown(pfsGroupOptions, values.pfsGroup, real ? [real.raw.pfsGroup] : []).map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </div>
      )}

      {isJuniper && (
        <div className="interface-configuration-form-field">
          <label className="data-label">WAN Interface</label>
          <select
            value={values.wanInterface}
            onChange={(event) => setField("wanInterface", event.target.value)}
            disabled={ifBriefLoading}
            required
          >
            <option value="">-- Select interface --</option>
            {interfaceOptions.map((name) => (
              <option key={name} value={name}>
                {name}
              </option>
            ))}
          </select>
        </div>
      )}

      {!isJuniper && (
        <div className="interface-configuration-form-field">
          <label className="data-label">Tunnel Mode</label>
          <div
            className={`segmented-control${ipsecReason ? " locked-choice" : ""}`}
            title={ipsecReason || undefined}
          >
            <input
              type="radio"
              id="mode-tunnel"
              name="tunnel-mode"
              value="tunnel"
              checked={values.tunnelMode === "tunnel"}
              disabled={Boolean(ipsecReason)}
              onChange={(event) => setField("tunnelMode", event.target.value)}
            />
            <label htmlFor="mode-tunnel">Tunnel</label>
            <input
              type="radio"
              id="mode-transport"
              name="tunnel-mode"
              value="transport"
              checked={values.tunnelMode === "transport"}
              disabled={Boolean(ipsecReason)}
              onChange={(event) => setField("tunnelMode", event.target.value)}
            />
            <label htmlFor="mode-transport">Transport</label>
          </div>
        </div>
      )}

      <div className="interface-form-btn-container">
        <button type="submit" className="btn btn-primary" disabled={submitting}>
          {submitting ? "Sending..." : isEdit ? "Save" : "OK"}
        </button>
        <button type="button" className="btn btn-ghost" onClick={onClose}>
          Cancel
        </button>
      </div>
    </form>
  );
}
