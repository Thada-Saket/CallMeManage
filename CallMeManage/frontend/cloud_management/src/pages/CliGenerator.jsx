import DismissibleError from "../components/DismissibleError";
// |===== Cli Generator Page =====|

import { useEffect, useRef, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import TopBar from "../components/TopBar";
import { generateCli, getCliServerInfo } from "../api/api_cli";
import { getDevice } from "../api/api_devices";
import { normalizeSubnet } from "../utils/normalizeSubnet";
import IPv4Input from "../components/common/IPv4Input";
import { validateIPv4Input } from "../utils/ipv4Input";
import { copyText } from "../utils/copyText";
import { createSingleFlight } from "../utils/singleFlight";
import {
  LOCAL_ADMIN_RESET,
  applyLocalAdminPayload,
  isPasswordValid,
  localAdminResetFor,
  passwordChecks,
  validateLocalAdmin,
} from "../utils/localAdmin";
import { cliGeneratorUrl, devicesUrl } from "../utils/deviceEnrollmentRoutes";
import { acceptsDomainNameInput, DOMAIN_NAME_MAX_LENGTH } from "../utils/domainNameInput";
import AutoSizeTextarea from "../components/common/AutoSizeTextarea";
import { cliStepHint } from "../utils/cliStepHints";

// แปลงวินาทีคงเหลือของ bootstrap download link ให้อยู่ในรูป mm:ss
function formatBootstrapRemaining(totalSeconds) {
  if (totalSeconds == null) return "--:--";
  const m = Math.floor(totalSeconds / 60);
  const s = totalSeconds % 60;
  return `${m.toString().padStart(2, "0")}:${s.toString().padStart(2, "0")}`;
}

// บังคับกรอก WAN IP / prefix จากนั้น validate ข้อมูลไว้สำหรับส่งไปทำงานตามยี่ห้อ
function parseWanCidr(raw) {
  const checked = validateIPv4Input(raw, {mode: "cidr"});
  if (!checked.valid) return null;
  const trimmed = raw.trim();
  const slashIndex = trimmed.indexOf("/");
  if (slashIndex === -1) return null;

  const ip = trimmed.slice(0, slashIndex).trim();
  const subnetPart = trimmed.slice(slashIndex + 1).trim();
  if (!ip || !subnetPart) return null;

  const subnet = normalizeSubnet(subnetPart);
  if (!subnet) return null;

  return { ip, prefix: subnet.prefix, subnetMask: subnet.subnetMask };
}

// นโยบายรหัสผ่านของ console user (บัญชีสำรองกัน console ล็อกตาย - เป็น privilege 15
// จริงบนอุปกรณ์) - ต้องตรงกับ _validate_console_password ใน backend/schema/schema.py
// เสมอ ถ้าแก้ที่นี่ต้องไปแก้ที่นั่นด้วย (frontend เช็คเพื่อ UX ส่วน backend เช็คเพื่อ
// ความถูกต้องจริง เพราะฝั่ง browser ข้ามได้ด้วยการยิง API ตรง)
//
// บังคับเฉพาะโหมด "new" เท่านั้น - โหมด existing ไม่ได้สร้าง console user เลย
// Cisco/Huawei วาง password ลง CLI แบบ plain - ห้ามช่องว่าง/ตัวอักษรนอก ASCII/อักขระที่ทำให้
// บรรทัด CLI พัง (ตรงกับ tools/console_user_policy.py)
const CONSOLE_PASSWORD_RULES = [
  { label: "8-25 characters long", test: (v) => v.length >= 8 && v.length <= 25 },
  { label: "No spaces, non-English characters, or ? \" ' \\ `", test: (v) => !/[^\x21-\x7E]|[?"'\\`]/.test(v) },
  { label: "Contains lowercase letter (a-z)", test: (v) => /[a-z]/.test(v) },
  { label: "Contains uppercase letter (A-Z)", test: (v) => /[A-Z]/.test(v) },
  { label: "Contains number (0-9)", test: (v) => /[0-9]/.test(v) },
  { label: "Contains special character (!@#$%^&* etc.)", test: (v) => /[^A-Za-z0-9]/.test(v) },
];

// นโยบายชื่อ console user - ต้องตรงกับ validate_console_username ใน tools/console_user_policy.py
// (Huawei CE12800 ไม่รับ local-user สั้นกว่า 6 ตัว จึงบังคับขั้นต่ำเฉพาะ Huawei)
function consoleUsernameRules(vendor, reservedUsername) {
  return [
    vendor === "huawei"
      ? { label: "6-32 characters long", test: (v) => v.length >= 6 && v.length <= 32 }
      : { label: "1-32 characters long", test: (v) => v.length >= 1 && v.length <= 32 },
    { label: "Starts with a letter or number", test: (v) => /^[A-Za-z0-9]/.test(v) },
    { label: "Only letters, numbers, period (.), underscore (_), hyphen (-)", test: (v) => /^[A-Za-z0-9._-]*$/.test(v) },
    {
      label: reservedUsername ? `Not "${reservedUsername}" (used by the system)` : "Not the system management username",
      test: (v) => !reservedUsername || v.toLowerCase() !== reservedUsername.toLowerCase(),
    },
  ];
}

// (bug 12) นโยบายชื่ออุปกรณ์ - ต้องตรงกับ tools/hostname_policy.py ฝั่ง backend เสมอ
// ถ้าแก้ที่นี่ต้องไปแก้ที่นั่นด้วย (ที่นั่นเป็นตัวจริงที่บังคับใช้ ที่นี่มีไว้เพื่อ UX)
//
// เดิมช่องนี้ไม่มีการตรวจอะไรเลยนอกจาก "ต้องไม่ว่าง" ผู้ใช้จึงกรอกยาว 500 ตัว /
// ภาษาไทย / emoji / เว้นวรรค / ขึ้นบรรทัดใหม่ ได้หมด ซึ่งค่าพวกนี้ถูกเอาไปวางลง
// ข้อความ CLI ตรง ๆ (เช่น "hostname <ค่าที่กรอก>") แล้วผู้ใช้ copy ไปวางบน console
// เอง - ชื่อที่มีเว้นวรรคจะทำให้อุปกรณ์รับแค่คำแรกหรือ error ทิ้งทั้งบรรทัด
// Domain Name บังคับกฎตั้งแต่ตอนพิมพ์แทนการโชว์ checklist ใต้ช่อง (ผู้ใช้ระบุว่า
// รายการนั้นรกเกินไป) - กฎอยู่ที่ utils/domainNameInput.js
const HOSTNAME_MAX_LENGTH = 32;
const HOSTNAME_RULES = [
  { label: `1-${HOSTNAME_MAX_LENGTH} characters long`, test: (v) => v.length >= 1 && v.length <= HOSTNAME_MAX_LENGTH },
  { label: "Allowed characters: A-Z, a-z, 0-9, hyphen (-), underscore (_)", test: (v) => /^[A-Za-z0-9_-]+$/.test(v) },
  { label: "Must not start or end with a hyphen (-)", test: (v) => /^[A-Za-z0-9_](?:.*[A-Za-z0-9_])?$/.test(v) },
];

// dropdown interface type สำหรับแต่ละยี่ห้อ
const IF_PREFIXES = {
  cisco: ["Ethernet", "FastEthernet", "GigabitEthernet", "TwoGigabitEthernet", "FiveGigabitEthernet", "TenGigabitEthernet", "FortyGigabitEthernet"],
  juniper: ["fe-", "ge-", "xe-", "et-"],
  huawei: ["GE", "10GE", "25GE", "40GE"],
};
// default prefix สำหรับอุปกรณ์แต่ละรุ่น เลือกได้
const IF_PREFIX_DEFAULT = { cisco: "GigabitEthernet", juniper: "ge-", huawei: "GE" };
const IF_ID_PLACEHOLDER = { cisco: "1", juniper: "0/0/0", huawei: "0/0/1" };
const HUAWEI_IF_ID_PATTERN = /^\d+\/\d+\/\d+$/;

function HelpHint({ label, invalid = false, children }) {
  return (
    <span className={`field-help${invalid ? " field-help-invalid" : ""}`}>
      <button type="button" className="field-help-trigger" aria-label={label}>?</button>
      <span className="field-help-tooltip" role="tooltip">{children}</span>
    </span>
  );
}

function PasswordPolicyHint({ checks, invalid = false }) {
  return (
    <HelpHint
      label={invalid ? "Password does not meet all requirements" : "Show password requirements"}
      invalid={invalid}
    >
      <strong>{invalid ? "Password does not meet all requirements" : "Password requirements"}</strong>
      <ul className="field-help-list">
        {checks.map((check) => (
          <li key={check.label} className={check.passed ? "hint-rule-pass" : "hint-rule-fail"}>
            <span aria-hidden="true">{check.passed ? "✓" : "○"}</span> {check.label}
          </li>
        ))}
      </ul>
    </HelpHint>
  );
}

function formatCreatedAt(value) {
  if (!value) return "Created just now";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Created just now";
  const seconds = Math.max(0, Math.floor((Date.now() - date.getTime()) / 1000));
  if (seconds < 60) return "Created just now";
  if (seconds < 3600) return `Created ${Math.floor(seconds / 60)} min ago`;
  if (seconds < 86400) return `Created ${Math.floor(seconds / 3600)} hr ago`;
  return `Created ${Math.floor(seconds / 86400)} days ago`;
}

// สร้าง CLI ให้ไปวางบนอุปกรณ์เปล่าๆ (ยังไม่เคย call-home เข้าระบบเลย) ให้มันตั้ง
// ค่าพื้นฐาน (hostname/ssh/netconf) + สั่งให้ call-home กลับมาหา server นี้เอง -
// ไม่มี username/password ให้กรอกแล้ว (auth คงที่เป็น SSH public key เดียวกัน
// ทุกยี่ห้อ ดู ADMIN_USERNAME และ tools/keys/rsa_public_key.pem ใน backend/cli_generator.py) -
// รายละเอียดคำสั่งจริงทั้งหมดอยู่ใน cli_generator.py ไฟล์นี้แค่เก็บ input ที่
// ต้องการแล้วยิงไป /cli/generate - เป็นหน้าเต็มแบ่งครึ่งจอ (ซ้ายกรอก ขวา
// output) แทนที่จะเป็น popup เพราะ popup แคบเกินไปเวลาต้องอ่าน CLI ยาวๆ
export default function CliGenerator() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const siteId = searchParams.get("site_id");
  const requestedPendingDeviceId = searchParams.get("pending_device_id");

  // page main value - send to backend for sending back cli
  const [values, setValues] = useState({
    vendor: "cisco", // cisco | juniper | huawei
    deviceMode: "new", // new device | existing device
    deviceRole: "router", // router | firewall | switch
    wanIfPrefix: IF_PREFIX_DEFAULT.cisco,
    wanIfId: "",
    wanMode: "dhcp", // wan interface type dhcp | static
    wanAddress: "",
    wanGateway: "", // only wan Mode = static
    wanDns: "", // only wan Mode = static
    hostname: "",
    domainName: "", // only cisco
    rootPasswd: "",  // only juniper have to set root password before commit - backend will automatically hash SHA-512 via openssl
    consoleUser: "", // prevent device console dead lock
    consolePass: "", // prevent device console dead lock
    ...LOCAL_ADMIN_RESET,
    cloudServerIp: "",
    cloudServerPort: "",
    bootstrapInterfaceType: "vlan", // vlan | layer3
    bootstrapVlanMode: "access", // access | trunk
    bootstrapVlanSelection: "default", // default (VLAN 1) | specific
    bootstrapVlanId: "",
    bootstrapIfPrefix: IF_PREFIX_DEFAULT.huawei,
    bootstrapIfId: "",
  });
  const [cliText, setCliText] = useState("");
  // devide cli into segments to prevented buffer overflow = especially juniper
  const [cliSegments, setCliSegments] = useState([]);
  const [cliSteps, setCliSteps] = useState([]);
  // show boilerplate config
  const [boilerplateText, setBoilerplateText] = useState("");

  // state copy state - copy / copied
  const [copied, setCopied] = useState(false);
  const [copiedSegments, setCopiedSegments] = useState({});
  const [copiedBoilerplate, setCopiedBoilerplate] = useState(false);
  // popup แสดง boilerplate ที่อุปกรณ์จะไปดาวน์โหลดเอง - เปิดจากขั้นตอนดาวน์โหลด
  // configuration (can_view_payload === true)
  const [showBoilerplate, setShowBoilerplate] = useState(false);

  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  // ผลของ Token Flow ที่เพิ่งสร้างสำเร็จ { id, name } - อยู่ใน state ของหน้านี้เท่านั้น (ไม่เก็บลง storage/URL/log)
  // ไม่เก็บ token ในตัวแปรแยก: token อยู่ได้เฉพาะในข้อความ CLI ที่ backend คืนมา
  const [pendingDevice, setPendingDevice] = useState(null);
  const [regenerationTarget, setRegenerationTarget] = useState(null);
  const [loadingRegenerationTarget, setLoadingRegenerationTarget] = useState(Boolean(requestedPendingDeviceId));
  // เวลาหมดอายุของ bootstrap download link (มีเฉพาะ cisco / juniper)
  const [bootstrapExpiresAt, setBootstrapExpiresAt] = useState(null);
  const [bootstrapRemainingSeconds, setBootstrapRemainingSeconds] = useState(null);

  // นับถอยหลังอายุของ Bootstrap download link (Cisco / Juniper)
  useEffect(() => {
    if (!bootstrapExpiresAt) {
      setBootstrapRemainingSeconds(null);
      return undefined;
    }

    const updateRemaining = () => {
      const expiryMs = new Date(bootstrapExpiresAt).getTime();
      const diffMs = expiryMs - Date.now();
      const seconds = Math.max(0, Math.floor(diffMs / 1000));
      setBootstrapRemainingSeconds(seconds);
    };

    updateRemaining();
    const timer = window.setInterval(updateRemaining, 1000);
    return () => {
      window.clearInterval(timer);
    };
  }, [bootstrapExpiresAt]);

  // กัน submit ซ้ำ (double click) แบบ synchronous + ทิ้งผลของ request ที่หมดความหมายแล้ว (ออกจากหน้า/เริ่มใหม่)
  const flightRef = useRef(createSingleFlight());
  const requestSeqRef = useRef(0);
  const mountedRef = useRef(true);
  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  // เปิดจากปุ่ม Regenerate บน Pending card: โหลด identity ที่ backend อนุญาตจริง
  // และให้ผู้ใช้กรอกค่าการตั้งค่าใหม่เอง (ค่าลับ/CLI เดิมไม่ถูก persist ใน browser)
  useEffect(() => {
    if (!requestedPendingDeviceId) {
      setRegenerationTarget(null);
      setLoadingRegenerationTarget(false);
      return;
    }
    let cancelled = false;
    setLoadingRegenerationTarget(true);
    getDevice(requestedPendingDeviceId)
      .then((device) => {
        if (cancelled) return;
        if (device.site_id !== siteId || device.dev_status !== "pending") {
          setError("This device is no longer waiting for enrollment.");
          setRegenerationTarget(null);
          return;
        }
        setRegenerationTarget({
          id: device.dev_id,
          name: device.dev_name || "",
          status: device.dev_status || "pending",
          createdAt: device.dev_added_date || null,
        });
        setValues((prev) => ({
          ...prev,
          vendor: device.dev_vendor,
          ...LOCAL_ADMIN_RESET,
          wanIfPrefix: IF_PREFIX_DEFAULT[device.dev_vendor],
          deviceRole: device.dev_vendor === "huawei" ? "router" : prev.deviceRole,
          wanMode: device.dev_vendor === "huawei" ? "static" : prev.wanMode,
          bootstrapInterfaceType: "vlan",
          bootstrapVlanMode: "access",
          bootstrapVlanSelection: "default",
          bootstrapVlanId: "",
          bootstrapIfPrefix: IF_PREFIX_DEFAULT[device.dev_vendor],
          bootstrapIfId: "",
        }));
      })
      .catch((err) => {
        if (!cancelled) setError(err.detail || "Failed to load the pending device.");
      })
      .finally(() => {
        if (!cancelled) setLoadingRegenerationTarget(false);
      });
    return () => {
      cancelled = true;
    };
  }, [requestedPendingDeviceId, siteId]);
  // autofill callhome server ip import from backend
  const [serverIpAutoFilled, setServerIpAutoFilled] = useState(false);
  // fix user for ssh import from backend
  const [adminUsername, setAdminUsername] = useState("");

  const INTERFACE_ID_TYPING_PATTERN = /^(?:\d+(?:\/\d*)*)?$/;
  const INTERFACE_ID_PATTERN = /^\d+(?:\/\d+)*$/;
  // after jsx render, this will run automatically and only one time
  useEffect(() => {
    let cancelled = false;
    // fetch callhome server info including ip, port
    getCliServerInfo()
      .then((info) => {
        if (cancelled) return;
        if (info?.cloud_server_ip) {
          setValues((prev) => ({ 
            ...prev, 
            cloudServerIp: info.cloud_server_ip, 
            cloudServerPort: info.cloud_server_port 
          }));
          setServerIpAutoFilled(true);
        }
        if (info?.admin_username) setAdminUsername(info.admin_username);
      })
      .catch(() => {
        
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // set value field
  // สลับ role ไป/กลับ switch เริ่มแผน bootstrap ใหม่เสมอ ไม่ให้ค่าที่ค้างจากรอบก่อน
  // (เช่น VLAN ID ที่เคยกรอกไว้) หลุดไปกับ payload ของอีกโหมด
  function setDeviceRole(role) {
    setValues((prev) => ({
      ...prev,
      deviceRole: role,
      bootstrapInterfaceType: "vlan",
      bootstrapVlanMode: "access",
      bootstrapVlanSelection: "default",
      bootstrapVlanId: "",
      bootstrapIfId: "",
    }));
  }

  function setField(name, value) {
    // เปลี่ยนไป New Device = ล้างค่า Local Administrator ทั้งหมด (ฟีเจอร์นี้มีเฉพาะ Existing Device)
    setValues((prev) => ({ ...prev, [name]: value, ...localAdminResetFor(name, value) }));
    setCopied(false);
    setCopiedSegments({});
    setCopiedBoilerplate(false);
  }

  // ปิด toggle = ล้าง username/password/confirm ทันที (ไม่ซ่อนแล้วเก็บค่าไว้ใน state)
  function handleLocalAdminToggle(enabled) {
    setValues((prev) => ({ ...prev, ...LOCAL_ADMIN_RESET, addLocalAdmin: enabled }));
  }

  function setBootstrapInterfaceType(type) {
    setValues((prev) => ({
      ...prev,
      bootstrapInterfaceType: type,
      bootstrapVlanMode: "access",
      bootstrapVlanSelection: "default",
      bootstrapVlanId: "",
      bootstrapIfId: "",
    }));
  }

  function setBootstrapVlanMode(mode) {
    setValues((prev) => ({
      ...prev,
      bootstrapVlanMode: mode,
      bootstrapVlanSelection: mode === "access" ? "default" : "",
      bootstrapVlanId: "",
      bootstrapIfId: "",
    }));
  }

  function setBootstrapVlanSelection(selection) {
    setValues((prev) => ({
      ...prev,
      bootstrapVlanSelection: selection,
      bootstrapVlanId: "",
      bootstrapIfId: "",
    }));
  }

  // handle vendors both fill nothing of fill some data
  function handleVendorChange(vendor) {
    // get old data and change some field
    setValues((prev) => ({
      ...prev,
      // change vendor
      vendor,
      ...LOCAL_ADMIN_RESET, // เปลี่ยน vendor = ล้างค่าลับ (กฎ username ต่างกันต่อ vendor)
      // change interface type into vendor supported form
      wanIfPrefix: IF_PREFIX_DEFAULT[vendor],
      // ซ่อนชนิดอุปกรณ์ของ Huawei แต่เก็บค่า router ภายในเพื่อไม่ให้กฎ switch
      // ของ Cisco/Juniper มาเปลี่ยนฟอร์ม bootstrap เฉพาะ Huawei
      deviceRole: vendor === "huawei" ? "router" : prev.deviceRole,
      // Huawei bootstrap บังคับ static; เปลี่ยนกลับยี่ห้ออื่นยังเลือกโหมดเองได้
      wanMode: vendor === "huawei" ? "static" : prev.wanMode,
      // ทุกยี่ห้อใช้แผน bootstrap ชุดเดียวกันแล้ว - เปลี่ยนยี่ห้อจึงรีเซ็ตกลับค่า
      // เริ่มต้นเสมอ (ไม่ใช่เฉพาะ Huawei) เพราะชื่อ prefix ของขาคนละชุดกันสิ้นเชิง
      // ถ้าคงค่าเก่าไว้จะได้ชื่อขาที่ไม่มีอยู่จริงบนยี่ห้อใหม่
      bootstrapInterfaceType: "vlan",
      bootstrapVlanMode: "access",
      bootstrapVlanSelection: "default",
      bootstrapVlanId: "",
      bootstrapIfPrefix: IF_PREFIX_DEFAULT[vendor],
      bootstrapIfId: "",
    }));
    setCopied(false);
    setCopiedSegments({});
    setCopiedBoilerplate(false);
  }

  // bool value - check device is switch or not 
  const isHuawei = values.vendor === "huawei";
  const isSwitch = values.deviceRole === "switch";
  // Router uses the WAN interface picker; switches use the bootstrap VLAN/Layer-3 plan.
  const wanInterfaceName = `${values.wanIfPrefix}${values.wanIfId.trim()}`;
  // bool check device is exist or not
  const isExisting = values.deviceMode === "existing";
  // ขา bootstrap เลือกได้ชุดเดียวกันทุกยี่ห้อแล้ว - Huawei ใช้เสมอในโหมด new
  // (CE12800 เป็นสวิตช์อยู่แล้ว) ส่วน Cisco/Juniper ใช้เมื่อเลือก role เป็น switch
  // role router ยังผูก IP กับ WAN interface ตรง ๆ เหมือนเดิม ไม่มี VLAN มาเกี่ยว
  const usesBootstrapPlan = !isExisting && (isHuawei || isSwitch);
  const isBootstrapLayer3 = usesBootstrapPlan && values.bootstrapInterfaceType === "layer3";
  const isBootstrapVlan = usesBootstrapPlan && values.bootstrapInterfaceType === "vlan";
  const isBootstrapAccess = isBootstrapVlan && values.bootstrapVlanMode === "access";
  const isBootstrapTrunk = isBootstrapVlan && values.bootstrapVlanMode === "trunk";
  const isBootstrapSpecificVlan = isBootstrapAccess && values.bootstrapVlanSelection === "specific";
  const showBootstrapVlanId = isBootstrapTrunk || isBootstrapSpecificVlan;
  const showBootstrapInterface = isBootstrapLayer3 || isBootstrapTrunk || isBootstrapSpecificVlan;
  const bootstrapInterfaceName = `${values.bootstrapIfPrefix}${values.bootstrapIfId.trim()}`;
  // Huawei บังคับรูปแบบ slot/card/port เต็ม ส่วน Cisco/Juniper ใช้กฎเดียวกับช่อง
  // WAN/Management ของตัวเอง (ตรงกับ validate_bootstrap_port ฝั่ง backend)
  const bootstrapIdPattern = isHuawei ? HUAWEI_IF_ID_PATTERN : INTERFACE_ID_PATTERN;
  // bool check wan interface is require or not
  const wanInterfaceRequired = !isExisting && !isHuawei;
  // hostname บังคับเฉพาะโหมด new เท่านั้นทุกยี่ห้อ - โหมด existing เป็น brownfield
  // ที่มี hostname ของตัวเองอยู่แล้ว ไม่ควรไปเขียนทับ (Juniper เคยต้องกรอกเพราะ
  // boilerplate เอาไปเติมช่อง device-id ของ outbound-ssh แต่ server ไม่เคยอ่านค่านั้น
  // เลย ตอนนี้ใช้ค่าคงที่แทนในโหมด existing - ดู generate_juniper)
  // hostname ไม่บังคับกรอกแล้วทุกยี่ห้อ (ผู้ใช้กำหนด) - ไม่กรอก = generator ไม่ออก
  // คำสั่งตั้งชื่อเลย อุปกรณ์คงชื่อเดิมไว้ · ช่องยังโชว์เฉพาะโหมด new เหมือนเดิม
  // เพราะโหมด existing ไม่เคยตั้งชื่อให้อยู่แล้ว
  const hostnameShown = !isExisting;

  // ทุกยี่ห้อสร้างบัญชี console สำรองในโหมด new เพื่อกู้การเข้าถึงเมื่อ key มีปัญหา
  const consoleUserRequired = !isExisting;

  // ประเมินรหัสผ่าน console ใหม่ทุกครั้งที่ผู้ใช้พิมพ์ (component re-render ทุกตัวอักษร
  // อยู่แล้วจาก setField) -> checklist ใต้ช่องกรอกจึงอัปเดตแบบ real-time เอง
  const consolePasswordChecks = CONSOLE_PASSWORD_RULES.map((rule) => ({
    label: rule.label,
    passed: rule.test(values.consolePass),
  }));
  const consolePasswordValid = consolePasswordChecks.every((check) => check.passed);
  const consoleUsernameChecks = consoleUsernameRules(values.vendor, adminUsername).map((rule) => ({
    label: rule.label,
    passed: rule.test(values.consoleUser.trim()),
  }));
  const consoleUsernameValid = consoleUsernameChecks.every((check) => check.passed);
  // Local Administrator: แสดง/ใช้เฉพาะ Existing Device และเมื่อเปิด toggle
  const localAdminEnabled = isExisting && values.addLocalAdmin;
  const localAdminPasswordChecks = passwordChecks(values.localAdminPass);
  const localAdminPasswordInvalid = Boolean(values.localAdminPass) && !isPasswordValid(values.localAdminPass);

  // ประเมินชื่ออุปกรณ์ทุกครั้งที่พิมพ์ (แพทเทิร์นเดียวกับรหัสผ่าน console ด้านบน)
  // ใช้ค่าที่ trim แล้วเพื่อให้ผลตรงกับค่าที่ส่งไป backend จริง (handleGenerate trim ก่อนส่ง)
  const hostnameChecks = HOSTNAME_RULES.map((rule) => ({
    label: rule.label,
    passed: rule.test(values.hostname.trim()),
  }));
  const hostnameValid = hostnameChecks.every((check) => check.passed);

  // ประเมินชื่อโดเมนแบบ real-time เหมือน hostname (แพทเทิร์นเดียวกัน)
  const wanIfId = values.wanIfId.trim();

  // when click generate button, form will active this function
  async function handleGenerate(event) {
    // stop default form behavior
    event.preventDefault();
    // ต้องมี Site context จาก URL (route guard บังคับแล้ว) - ไม่ fallback ไปสร้าง CLI แบบ legacy โดยไม่มี Site
    // กัน double click เท่านั้น; ถ้ามี pendingDevice จะ Regenerate แถวเดิมแทนการสร้างอุปกรณ์เพิ่ม
    if (!siteId) return setError("Select a Site before generating a CLI.");
    if (flightRef.current.busy) return;
    setError("");
    setCliText("");
    setCliSegments([]);
    setBoilerplateText("");
    setShowBoilerplate(false);
    setBootstrapExpiresAt(null);

    // get hostname from values variable
    const hostname = values.hostname.trim();
    // get cloud server ip
    const cloudServerIp = values.cloudServerIp.trim();

    // prevent error - if wan is require, not a switch and no have wan information
    if (wanInterfaceRequired && !isSwitch && !values.wanIfId.trim()) {
      return setError("Enter the WAN interface ID.");
    }

    if (
      wanInterfaceRequired &&
      !isSwitch &&
      !INTERFACE_ID_PATTERN.test(wanIfId)
    ) {
      return setError(
        "WAN Interface ID must be slash-separated numbers, e.g. 1, 1/0, or 1/0/24"
      );
    }
    // prevent error - not enter hostname

    // prevent error - hostname ผิดนโยบาย (เช็คเฉพาะโหมดที่ใช้ hostname จริง - โหมด
    // existing ไม่ตั้ง hostname ให้อุปกรณ์เลย จึงไม่ต้องบังคับรูปแบบ)
    // ตรวจนโยบายเฉพาะตอนที่กรอกมาจริง - เว้นว่างถือว่า "ไม่เปลี่ยนชื่ออุปกรณ์"
    if (hostnameShown && hostname && !hostnameValid) {
      const unmet = hostnameChecks.filter((c) => !c.passed).map((c) => c.label);
      return setError(`Device name does not meet requirements: ${unmet.join(", ")}`);
    }
    // prevent error - not enter cloud ip
    if (!cloudServerIp) return setError("Enter Cloud Server IP");
    if (!validateIPv4Input(cloudServerIp).valid) {
      return setError("Cloud Server IP must be a valid IPv4 address.");
    }
    // prevent error - cisco not input domain name
    if (values.vendor === "cisco" && !isExisting && !values.domainName.trim()) {
      return setError("Enter the Domain Name (required for Cisco New Deployment).");
    }
    // prevent error - juniper not input root password
    if (values.vendor === "juniper" && !isExisting && !values.rootPasswd) {
      return setError("Enter the Root Password (required for Juniper New Deployment).");
    }
    // prevent error - console user ไม่ผ่านนโยบายรหัสผ่าน (เฉพาะ vendor/โหมดที่สร้าง user นี้จริง)
    if (consoleUserRequired) {
      if (!values.consoleUser.trim()) return setError("Enter the Device CLI Username.");
      // CE12800 ไม่รับ local-user ที่ชื่อสั้นกว่า 6 ตัวอักษร - กฎนี้อยู่ใน consoleUsernameRules
      // แล้ว (เฉพาะ Huawei) พร้อมกฎ charset ที่กันชื่อแทรกคำสั่งลง CLI
      if (!consoleUsernameValid) {
        const unmet = consoleUsernameChecks.filter((c) => !c.passed).map((c) => c.label);
        return setError(`Device CLI Username does not meet requirements: ${unmet.join(", ")}`);
      }
      if (!consolePasswordValid) {
        const unmet = consolePasswordChecks.filter((c) => !c.passed).map((c) => c.label);
        return setError(`Console password does not meet requirements: ${unmet.join(", ")}`);
      }
    }

    // Local Administrator (ข้อความ error ไม่ใส่ค่าที่กรอก)
    if (localAdminEnabled) {
      const localAdminError = validateLocalAdmin({
        vendor: values.vendor,
        username: values.localAdminUser,
        password: values.localAdminPass,
        reservedUsername: adminUsername,
      });
      if (localAdminError) return setError(localAdminError);
    }

    if (usesBootstrapPlan) {
      if (showBootstrapInterface && !values.bootstrapIfId.trim()) {
        return setError("Enter the bootstrap interface ID.");
      }
      if (showBootstrapInterface && !bootstrapIdPattern.test(values.bootstrapIfId.trim())) {
        return setError(isHuawei
          ? "Huawei interface ID must look like 1/0/1."
          : "Interface ID must be slash-separated numbers, e.g. 1, 1/0, or 1/0/24");
      }
      if (showBootstrapVlanId) {
        const vlanId = Number(values.bootstrapVlanId);
        if (!Number.isInteger(vlanId) || vlanId < 1 || vlanId > 4094) {
          return setError("VLAN ID must be between 1 and 4094.");
        }
      }
    }

    const payload = {
      // Site ที่ผ่าน route guard จาก URL เท่านั้น - backend ตรวจสิทธิ์จริงอีกชั้น (frontend ไม่ใช่ security boundary)
      // ไม่ส่ง token/hash ใด ๆ จาก browser: backend เป็นผู้สร้าง Enrollment Token เอง
      site_id: siteId,
      vendor: values.vendor,
      hostname,
      cloud_server_ip: cloudServerIp,
      cloud_server_port: Number(values.cloudServerPort),
      device_mode: values.deviceMode,
      device_role: values.deviceRole,
      wan_mode: isHuawei ? "static" : (isExisting ? "dhcp" : values.wanMode),
    };
    const regenerationDevice = pendingDevice || regenerationTarget;
    if (regenerationDevice?.id) payload.pending_device_id = regenerationDevice.id;
    // switch ไม่ส่ง wan_interface แล้ว - ชื่อขาที่ใช้จริงมาจากแผน bootstrap
    // (เดิมบังคับส่ง "Vlan1"/"vlan" ตายตัวซึ่งตอนนี้เลือกได้แล้ว)
    if (!isHuawei && !isSwitch) payload.wan_interface = wanInterfaceName;

    if (usesBootstrapPlan) {
      payload.bootstrap_interface_type = values.bootstrapInterfaceType;
      if (isBootstrapVlan) {
        payload.bootstrap_vlan_mode = values.bootstrapVlanMode;
        if (isBootstrapAccess) payload.bootstrap_vlan_selection = values.bootstrapVlanSelection;
        if (showBootstrapVlanId) payload.bootstrap_vlan_id = Number(values.bootstrapVlanId);
      }
      if (showBootstrapInterface) payload.bootstrap_interface = bootstrapInterfaceName;
    }

    // console user สร้างในทุก vendor ของโหมด new เพื่อให้ generator มีค่าที่ใช้สร้างบัญชีสำรอง
    // ไม่ส่งค่าว่างไป เพราะ validator ฝั่ง backend จะได้ไม่ต้องมาแยกแยะว่า "" คือยังไม่กรอก
    if (consoleUserRequired) {
      payload.console_username = values.consoleUser.trim();
      payload.console_password = values.consolePass;
    }
    // Local Administrator: ส่งเฉพาะ flag + username + password เมื่อเปิด (ไม่ส่ง confirm; ปิด = ไม่มี field เหล่านี้เลย)
    applyLocalAdminPayload(payload, {
      enabled: localAdminEnabled,
      username: values.localAdminUser,
      password: values.localAdminPass,
    });
    // add domain_name into payload for cisco
    if (values.vendor === "cisco" && !isExisting) payload.domain_name = values.domainName.trim();
    // add root_passwd into payload for juniper
    if (values.vendor === "juniper" && !isExisting) payload.root_passwd = values.rootPasswd;
    // new deploymenet device and set wan to static
    if (!isExisting && (isHuawei || values.wanMode === "static")) {
      const wan = parseWanCidr(values.wanAddress);
      if (!wan) return setError("Enter a valid WAN IP address and Prefix (0–32).");
      const wanGateway = values.wanGateway.trim();
      const wanDns = values.wanDns.trim();
      if (!wanGateway) return setError("Enter the WAN Gateway.");
      if (!validateIPv4Input(wanGateway).valid) {
        return setError("WAN Gateway must be a valid IPv4 address.");
      }

      if (wanDns && !validateIPv4Input(wanDns).valid) {
        return setError("DNS Server must be a valid IPv4 address.");
      }
      // add ip, subnet, gateway, dns to payload
      payload.wan_ip = wan.ip;
      payload.wan_mask = wan.subnetMask;
      payload.wan_prefix = wan.prefix;
      payload.wan_gateway = wanGateway;
      if (wanDns) payload.wan_dns = wanDns;
    }

    setSubmitting(true);
    const requestId = requestSeqRef.current + 1;
    requestSeqRef.current = requestId;
    let started = false;

    try {
      // call generate cli api to backend (single-flight: คลิกซ้ำไม่ยิง POST ที่สอง)
      const outcome = await flightRef.current.run(() => generateCli(payload));
      if (outcome.skipped) return;
      started = true;
      if (!mountedRef.current || requestId !== requestSeqRef.current) return;
      const result = outcome.value;
      // bring the results and show it on webpage
      setCliText(result.cli || "");
      setCliSegments(result.cli_segments || []);
      setCliSteps(result.cli_steps || []);
      setBoilerplateText(result.boilerplate || "");
      setBootstrapExpiresAt(result.bootstrap_expires_at || null);
      setValues((prev) => ({ ...prev, ...LOCAL_ADMIN_RESET })); // สำเร็จแล้วล้างค่าลับทันที
      setPendingDevice(
        result.pending_device_id
          ? {
            id: result.pending_device_id,
            name: result.pending_device_name || "",
            status: result.pending_device_status || "pending",
            createdAt: result.pending_device_created_at || new Date().toISOString(),
          }
          : null
      );
      setRegenerationTarget(null);
    } catch (err) {
      started = true;
      if (mountedRef.current && requestId === requestSeqRef.current) {
        setError(err.detail || "Failed to generate CLI.");
      }
    } finally {
      if (started && mountedRef.current) setSubmitting(false);
    }
  }

  // เริ่มสร้างอุปกรณ์ตัวใหม่: ล้างผลเก่าทั้งหมดก่อน (ไม่ให้ CLI/ชื่อของตัวเก่าปนกับ request ใหม่) - ค่าในฟอร์มยังอยู่
  function handleGenerateAnother() {
    if (flightRef.current.busy) return;
    requestSeqRef.current += 1;
    setPendingDevice(null);
    setRegenerationTarget(null);
    setCliText("");
    setCliSegments([]);
    setCliSteps([]);
    setBoilerplateText("");
    setShowBoilerplate(false);
    setCopied(false);
    setCopiedSegments({});
    setCopiedBoilerplate(false);
    setError("");
    setBootstrapExpiresAt(null);
    setValues((prev) => ({ ...prev, ...LOCAL_ADMIN_RESET })); // ล้างค่าลับของ Local Administrator
    navigate(cliGeneratorUrl(siteId), { replace: true });
  }

  // หลังสร้าง CLI แล้วอ่านสถานะจาก Device API เป็นระยะ เพื่อให้การ์ดเปลี่ยนเป็น
  // Online ทันทีเมื่ออุปกรณ์ Call Home สำเร็จ โดยไม่ส่งคำสั่ง NETCONF เพิ่ม
  useEffect(() => {
    if (!pendingDevice?.id) return undefined;
    let cancelled = false;
    const poll = async () => {
      try {
        const device = await getDevice(pendingDevice.id);
        if (cancelled) return;
        setPendingDevice((prev) => (prev ? {
          ...prev,
          name: device.dev_name || prev.name,
          status: device.dev_status || prev.status,
          createdAt: device.dev_added_date || prev.createdAt,
        } : prev));
      } catch {
        // อุปกรณ์ยังไม่พร้อม/หน้าเปลี่ยน ไม่แสดง error ทับ CLI ที่ผู้ใช้กำลัง copy
      }
    };
    poll();
    const timer = window.setInterval(poll, 3000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [pendingDevice?.id]);

  // copyText() มีทางสำรองให้ origin ที่ไม่ใช่ HTTPS/localhost ซึ่งเป็นสาเหตุที่
  // ปุ่มคัดลอกเคยพังทุกครั้ง (ดู utils/copyText.js)
  const COPY_FAILED = "Failed to copy. Please select the text manually and copy it.";

  async function handleCopy() {
    if (await copyText(cliText)) setCopied(true);
    else setError(COPY_FAILED);
  }

  async function handleCopySegment(index, text) {
    if (await copyText(text)) setCopiedSegments((prev) => ({ ...prev, [index]: true }));
    else setError(COPY_FAILED);
  }

  async function handleCopyBoilerplate() {
    if (await copyText(boilerplateText)) setCopiedBoilerplate(true);
    else setError(COPY_FAILED);
  }

  const effectiveSteps = cliSteps.length > 0
    ? cliSteps
    : cliSegments.map((segment, index) => ({
        id: `part-${index + 1}`,
        label: `Part ${index + 1}`,
        commands: segment,
        can_view_payload: index === cliSegments.length - 1 && Boolean(boilerplateText),
        requires_manual_commit_before_next: false,
      }));
  const renderedSteps = effectiveSteps.filter((step) => Boolean(step && step.commands && step.commands.trim()));
  const enrollmentStatus = pendingDevice?.status || "pending";
  const enrollmentOnline = ["active", "online"].includes(enrollmentStatus);
  const enrollmentStatusText = enrollmentOnline
    ? "Online"
    : enrollmentStatus === "offline"
      ? "Offline"
    : enrollmentStatus === "unresponsive"
      ? "Unresponsive"
      : "Waiting for device";
  const enrollmentStatusClass = enrollmentOnline
    ? "badge-active"
    : enrollmentStatus === "offline"
      ? "badge-offline"
      : "badge-pending";
  const enrollmentStep = enrollmentOnline ? 3 : 2;

  // ปิดท้ายใต้ขั้นสุดท้าย - ผู้ใช้เลื่อนลงมาถึงตรงนี้อยู่แล้วตอนวางคำสั่งเสร็จ จึงบอกว่าออกจากหน้าได้
  // และมีปุ่มไปต่อ ; ป้ายสถานะใช้ค่าเดียวกับการ์ดด้านบน (polling ชุดเดิม ไม่เช็คเพิ่ม)
  const doneCard = pendingDevice && (
    <div className="cli-generator-done">
      <div className="cli-generator-done-text">
        <strong>Done pasting?</strong>
        <span>You can leave this page. The device shows up on Devices by itself once it connects.</span>
      </div>
      <span className={`badge ${enrollmentStatusClass}`}>{enrollmentStatusText}</span>
      <div className="cli-generator-done-actions">
        <button type="button" className="btn btn-primary" onClick={() => navigate(devicesUrl(siteId))}>
          Back to Devices
        </button>
        <button type="button" className="btn btn-ghost" onClick={handleGenerateAnother}>
          + Enroll another device
        </button>
      </div>
    </div>
  );

  return (
    <div className="app-shell">
      <TopBar />
      <main className="main-content">
        <div className="page-header">
          <div>
            <h1>CLI Generate</h1>
            <div className="page-subtitle">
              Create a command that can be pasted into an unprovisioned device to make it call home to this server automatically.
            </div>
          </div>
            <button type="button" className="btn btn-primary detail-back" onClick={() => navigate(devicesUrl(siteId))}>
            &larr; Back to Devices
          </button>
        </div>

        <div className="cli-generator-layout">
          <div className="cli-generator-form-panel detail-panel">
            <h2>Device Information</h2>
            {regenerationTarget && (
              <div className="cli-generator-enrollment-notice" role="status">
                <strong>Regenerating {regenerationTarget.name}</strong>
                <p className="field-hint">
                  Enter the corrected values below. Saving will renew this pending device for another 24 hours and
                  invalidate its previous CLI.
                </p>
              </div>
            )}
            <form onSubmit={handleGenerate}>
              {error && <DismissibleError message={error} onDismiss={() => setError("")} />}

              <div className="field">
                <label htmlFor="cli-vendor">Vendor</label>
                <select id="cli-vendor" value={values.vendor} onChange={(event) => handleVendorChange(event.target.value)}>
                  <option value="cisco">Cisco IOS-XE</option>
                  <option value="juniper">Juniper Junos</option>
                  <option value="huawei">Huawei VRP</option>
                </select>
              </div>

              {values.vendor !== "huawei" && (
                <div className="field">
                  <label>Device Type</label>
                  <div className="segmented-control">
                    <input
                      type="radio"
                      id="cli-role-router"
                      name="cli-device-role"
                      value="router"
                      checked={values.deviceRole === "router"}
                      onChange={(event) => setDeviceRole(event.target.value)}
                    />
                    <label htmlFor="cli-role-router">Router / Firewall</label>
                    <input
                      type="radio"
                      id="cli-role-switch"
                      name="cli-device-role"
                      value="switch"
                      checked={values.deviceRole === "switch"}
                      onChange={(event) => setDeviceRole(event.target.value)}
                    />
                    <label htmlFor="cli-role-switch">Switch</label>
                  </div>
                </div>
              )}

              <div className="field">
                <div className="field-label-with-hint">
                  <label>Device Mode</label>
                  <HelpHint label="Explain device modes">
                    <strong>Choose how this device should be prepared</strong>
                    <span><b>Fresh Out of the Box:</b> for a new or unconfigured device. The generated CLI includes its initial setup.</span>
                    <span><b>Device With Existing Configuration:</b> preserves the current configuration and adds only the settings needed to connect it to this system.</span>
                  </HelpHint>
                </div>
                <div className="segmented-control">
                  <input
                    type="radio"
                    id="cli-mode-new"
                    name="cli-device-mode"
                    value="new"
                    checked={values.deviceMode === "new"}
                    onChange={(event) => setField("deviceMode", event.target.value)}
                  />
                  <label htmlFor="cli-mode-new">Fresh Out of the Box</label>
                  <input
                    type="radio"
                    id="cli-mode-existing"
                    name="cli-device-mode"
                    value="existing"
                    checked={values.deviceMode === "existing"}
                    onChange={(event) => setField("deviceMode", event.target.value)}
                  />
                  <label htmlFor="cli-mode-existing">Device With Existing Configuration</label>
                </div>
              </div>

              {!isHuawei && wanInterfaceRequired && !isSwitch && (
                <div className="field">
                  <label htmlFor="cli-wan-if-id">WAN Interface *</label>
                  <div className="interface-picker">
                    <select
                      id="cli-wan-if-prefix"
                      value={values.wanIfPrefix}
                      onChange={(event) => setField("wanIfPrefix", event.target.value)}
                    >
                      {IF_PREFIXES[values.vendor].map((prefix) => (
                        <option key={prefix} value={prefix}>{prefix}</option>
                      ))}
                    </select>
                    <input
                      id="cli-wan-if-id"
                      type="text"
                      inputMode="text"
                      pattern="[0-9]+(?:/[0-9]+)*"
                      placeholder={IF_ID_PLACEHOLDER[values.vendor]}
                      value={values.wanIfId}
                      onChange={(event) => {
                        const nextValue = event.target.value;
                        if (INTERFACE_ID_TYPING_PATTERN.test(nextValue)) {
                          setField("wanIfId", nextValue);
                        }
                      }}
                      required
                    />
                  </div>
                </div>
              )}

              {!isExisting && (
                <div className="field">
                  <div className="field-label-with-hint">
                    <label>IP Mode</label>
                    <HelpHint label="Explain IP modes">
                      {isSwitch || isHuawei ? (
                        <>
                          <strong>How the switch gets the IP it uses to contact the server</strong>
                          {!isHuawei && (
                            <span><b>DHCP:</b> the switch gets an IP automatically from a DHCP server on the uplink network (usually the router). Choose this if your network already gives out IPs automatically.</span>
                          )}
                          <span><b>Static:</b> you enter the IP address, gateway and DNS yourself. Choose this if there is no DHCP server, or the switch needs a fixed management IP.</span>
                          {isHuawei && (
                            <span>Huawei switches support <b>Static</b> only.</span>
                          )}
                        </>
                      ) : (
                        <>
                          <strong>How the WAN port gets its IP to reach the internet and this server</strong>
                          <span><b>DHCP:</b> the WAN port gets an IP automatically from the ISP modem or upstream router. Choose this for most internet links that give out IPs automatically.</span>
                          <span><b>Static:</b> you enter the IP address, gateway and DNS yourself. Choose this if your ISP or network admin gave you a fixed IP.</span>
                        </>
                      )}
                    </HelpHint>
                  </div>
                  <div className="segmented-control">
                    {!isHuawei && (
                      <>
                        <input
                          type="radio"
                          id="cli-wan-dhcp"
                          name="cli-wan-mode"
                          value="dhcp"
                          checked={values.wanMode === "dhcp"}
                          onChange={(event) => setField("wanMode", event.target.value)}
                        />
                        <label htmlFor="cli-wan-dhcp">DHCP</label>
                      </>
                    )}
                    <input
                      type="radio"
                      id="cli-wan-static"
                      name="cli-wan-mode"
                      value="static"
                      checked={isHuawei || values.wanMode === "static"}
                      onChange={(event) => setField("wanMode", event.target.value)}
                    />
                    <label htmlFor="cli-wan-static">Static</label>
                  </div>
                </div>
              )}

              {usesBootstrapPlan && (
                <>
                  <div className="field">
                    <div className="field-label-with-hint">
                      <label>Bootstrap Interface Type</label>
                      <HelpHint label="Explain bootstrap interface types">
                        <strong>Where the switch puts its IP to call home to the server</strong>
                        <span>This is the link that goes up to the router or the internet. The switch uses it to contact the server for the first time.</span>
                        <span><b>Layer 3 Interface:</b> one physical port becomes a routed port (it stops working as a normal switch port), and the IP is set directly on it, e.g. GigabitEthernet1/0/1. Choose this when one port connects straight to the router and carries nothing else.</span>
                        <span><b>VLAN Interface:</b> a virtual interface for a VLAN (Cisco <i>Vlan</i>, Juniper <i>irb</i>, Huawei <i>Vlanif</i>). The IP belongs to the VLAN, so any port in that VLAN can reach it, and the ports still work as normal switch ports. Choose this for a normal switch setup.</span>
                      </HelpHint>
                    </div>
                    <div className="segmented-control">
                      <input
                        type="radio"
                        id="bootstrap-interface-layer3"
                        name="bootstrap-interface-type"
                        value="layer3"
                        checked={values.bootstrapInterfaceType === "layer3"}
                        onChange={(event) => setBootstrapInterfaceType(event.target.value)}
                      />
                      <label htmlFor="bootstrap-interface-layer3">Layer 3 Interface</label>
                      <input
                        type="radio"
                        id="bootstrap-interface-vlan"
                        name="bootstrap-interface-type"
                        value="vlan"
                        checked={values.bootstrapInterfaceType === "vlan"}
                        onChange={(event) => setBootstrapInterfaceType(event.target.value)}
                      />
                      <label htmlFor="bootstrap-interface-vlan">VLAN Interface</label>
                    </div>
                  </div>

                  {isBootstrapVlan && (
                    <div className="field">
                      <div className="field-label-with-hint">
                        <label>VLAN Mode</label>
                        <HelpHint label="Explain VLAN modes">
                          <strong>How the uplink port (toward the router / server) carries VLANs</strong>
                          <span><b>Access:</b> the port belongs to one VLAN only and sends traffic without VLAN tags. Choose this when the other end is a normal router or modem port.</span>
                          <span><b>Trunk:</b> the port carries several VLANs, each marked with a VLAN tag (802.1Q). Choose this when the other end is also a trunk, such as a router sub-interface or another switch. The VLAN you enter below is allowed through it.</span>
                        </HelpHint>
                      </div>
                      <div className="segmented-control">
                        <input
                          type="radio"
                          id="bootstrap-vlan-access"
                          name="bootstrap-vlan-mode"
                          value="access"
                          checked={values.bootstrapVlanMode === "access"}
                          onChange={(event) => setBootstrapVlanMode(event.target.value)}
                        />
                        <label htmlFor="bootstrap-vlan-access">Access</label>
                        <input
                          type="radio"
                          id="bootstrap-vlan-trunk"
                          name="bootstrap-vlan-mode"
                          value="trunk"
                          checked={values.bootstrapVlanMode === "trunk"}
                          onChange={(event) => setBootstrapVlanMode(event.target.value)}
                        />
                        <label htmlFor="bootstrap-vlan-trunk">Trunk</label>
                      </div>
                    </div>
                  )}

                  {isBootstrapAccess && (
                    <div className="field">
                      <div className="field-label-with-hint">
                        <label>Access VLAN</label>
                        <HelpHint label="Explain access VLAN options">
                          <strong>Which VLAN the switch IP and uplink port use</strong>
                          <span><b>Default (VLAN 1):</b> uses VLAN 1, which every port is already in on a new switch. No port settings are changed. Just plug the uplink cable into any port.</span>
                          <span><b>Specific:</b> uses another VLAN that you choose, such as a management VLAN. The system creates that VLAN, puts the port you select into it, and sets the IP on that VLAN. The VLAN must match the one on the router side.</span>
                        </HelpHint>
                      </div>
                      <div className="segmented-control">
                        <input
                          type="radio"
                          id="bootstrap-vlan-default"
                          name="bootstrap-vlan-selection"
                          value="default"
                          checked={values.bootstrapVlanSelection === "default"}
                          onChange={(event) => setBootstrapVlanSelection(event.target.value)}
                        />
                        <label htmlFor="bootstrap-vlan-default">Default (VLAN 1)</label>
                        <input
                          type="radio"
                          id="bootstrap-vlan-specific"
                          name="bootstrap-vlan-selection"
                          value="specific"
                          checked={values.bootstrapVlanSelection === "specific"}
                          onChange={(event) => setBootstrapVlanSelection(event.target.value)}
                        />
                        <label htmlFor="bootstrap-vlan-specific">Specific</label>
                      </div>
                    </div>
                  )}

                  {showBootstrapVlanId && (
                    <div className="field">
                      <div className="field-label-with-hint">
                        <label htmlFor="bootstrap-vlan-id">VLAN ID *</label>
                        <HelpHint label="Explain VLAN ID">
                          <strong>The VLAN that carries traffic to the server</strong>
                          {isBootstrapTrunk ? (
                            <span>The trunk port lets this VLAN through, and the switch IP is set on it. Use the same VLAN ID as on the router or upstream switch, otherwise the switch cannot reach the server.</span>
                          ) : (
                            <span>The selected port joins this VLAN, and the switch IP is set on it. Use the same VLAN as the router side.</span>
                          )}
                          <span>Allowed range: 1-4094.</span>
                        </HelpHint>
                      </div>
                      <input
                        id="bootstrap-vlan-id"
                        type="number"
                        min="1"
                        max="4094"
                        value={values.bootstrapVlanId}
                        onChange={(event) => setField("bootstrapVlanId", event.target.value)}
                        required
                      />
                    </div>
                  )}

                  {showBootstrapInterface && (
                    <div className="field">
                      <label htmlFor="bootstrap-interface-id">Interface *</label>
                      <div className="interface-picker">
                        <select
                          id="bootstrap-interface-prefix"
                          value={values.bootstrapIfPrefix}
                          onChange={(event) => setField("bootstrapIfPrefix", event.target.value)}
                        >
                          {IF_PREFIXES[values.vendor].map((prefix) => (
                            <option key={prefix} value={prefix}>{prefix}</option>
                          ))}
                        </select>
                        <input
                          id="bootstrap-interface-id"
                          type="text"
                          inputMode="text"
                          pattern="[0-9]+(?:/[0-9]+)*"
                          placeholder={IF_ID_PLACEHOLDER[values.vendor]}
                          value={values.bootstrapIfId}
                          onChange={(event) => {
                            const nextValue = event.target.value;
                            if (INTERFACE_ID_TYPING_PATTERN.test(nextValue)) {
                              setField("bootstrapIfId", nextValue);
                            }
                          }}
                          required
                        />
                      </div>
                    </div>
                  )}
                </>
              )}

              {!isExisting && (isHuawei || values.wanMode === "static") && (
                <>
                  <div className="field">
                    <div className="data-label">{isSwitch ? "Static IPv4" : "WAN IPv4"} *</div>
                    <IPv4Input mode="cidr" label={isSwitch ? "Static IP" : "WAN IP"}
                      id="cli-wan-addr"
                      value={values.wanAddress}
                      onChange={(value) => setField("wanAddress", value)}
                      required
                    />
                  </div>
                  <div className="field">
                    <label htmlFor="cli-wan-gw">{isSwitch ? "Default Gateway" : "WAN Gateway"} *</label>
                    <IPv4Input
                      id="cli-wan-gw"
                      label={isSwitch ? "Default Gateway" : "WAN Gateway"}
                      value={values.wanGateway}
                      onChange={(value) => setField("wanGateway", value)}
                      required
                    />
                  </div>
                  <div className="field">
                    <label htmlFor="cli-wan-dns">DNS Server</label>
                    {/* ไม่กรอก = ไม่ออกคำสั่งตั้ง DNS เลย อุปกรณ์คงค่าเดิมไว้
                        (แนวเดียวกับช่อง Device Name) - bootstrap ไม่ต้องใช้ DNS
                        อยู่แล้วเพราะ URL ที่ให้อุปกรณ์ไปโหลด config เป็น IP ตรง ๆ */}
                    <IPv4Input
                      id="cli-wan-dns"
                      label="DNS Server"
                      value={values.wanDns}
                      onChange={(value) => setField("wanDns", value)}
                    />
                  </div>
                </>
              )}
              
              {hostnameShown && (
                <div className="field">
                  <label htmlFor="cli-hostname">Device Name</label>
                  <input
                    id="cli-hostname"
                    type="text"
                    placeholder="EDGE-BRANCH1"
                    value={values.hostname}
                    maxLength={HOSTNAME_MAX_LENGTH}
                    onChange={(event) => setField("hostname", event.target.value)}
                  />
                  {/* checklist อัปเดตทุกตัวอักษรที่พิมพ์ (เงื่อนไขชุดเดียวกับ
                      tools/hostname_policy.py ฝั่ง backend) - maxLength กันความยาว
                      ไว้อีกชั้นตั้งแต่ระดับ browser แต่ backend ยังต้องเช็คซ้ำเสมอ
                      เพราะยิง API ตรงข้ามหน้าเว็บได้ */}
                  {values.hostname && (
                  <ul className="password-policy-list">
                    {hostnameChecks.map((check) => (
                      <li
                        key={check.label}
                        className={check.passed ? "policy-pass" : "policy-fail"}
                      >
                        <span aria-hidden="true">{check.passed ? "✓" : "○"}</span> {check.label}
                      </li>
                    ))}
                  </ul>
                  )}
                </div>
              )}

              {values.vendor === "cisco" && !isExisting && (
                <div className="field">
                  <label htmlFor="cli-domain">Domain Name *</label>
                  <input
                    id="cli-domain"
                    type="text"
                    placeholder="corp.local"
                    value={values.domainName}
                    maxLength={DOMAIN_NAME_MAX_LENGTH}
                    onChange={(event) => {
                      if (acceptsDomainNameInput(event.target.value)) setField("domainName", event.target.value);
                    }}
                    required
                  />
                </div>
              )}

              {values.vendor === "juniper" && !isExisting && (
                <div className="field">
                  <div className="field-label-with-hint">
                    <label htmlFor="cli-root-passwd">Root Password *</label>
                    <HelpHint label="Explain Juniper root password">
                      <strong>Password for Juniper&apos;s built-in root account</strong>
                      <span><b>What it is:</b> root is the main admin account that every Juniper device has.</span>
                      <span><b>Why it is required:</b> a new Juniper device will not save (commit) any configuration until the root password is set. Without it, the generated CLI cannot be applied.</span>
                      <span>The password is put in the CLI only as an encrypted hash, never as plain text. Keep it safe. It is your last way to log in if every other account fails.</span>
                    </HelpHint>
                  </div>
                  <input
                    id="cli-root-passwd"
                    type="password"
                    placeholder="Set root password for commit"
                    value={values.rootPasswd}
                    onChange={(event) => setField("rootPasswd", event.target.value)}
                    required
                  />
                </div>
              )}

              {consoleUserRequired && (
                <div className="field">
                  <div className="field-label-with-hint">
                    <label>Device CLI Username *</label>
                    <HelpHint
                      label="Explain Device CLI Username"
                      invalid={Boolean(values.consoleUser) && !consoleUsernameValid}
                    >
                      <strong>A backup admin account on the device</strong>
                      <span><b>Why:</b> this system manages the device with an SSH key. If the key or the connection to the server stops working, you can still log in to the console or SSH with this username and the password below, so you are never locked out.</span>
                      <span><b>Requirements:</b></span>
                      <ul className="field-help-list">
                        {consoleUsernameChecks.map((check) => (
                          <li key={check.label} className={check.passed ? "hint-rule-pass" : "hint-rule-fail"}>
                            <span aria-hidden="true">{check.passed ? "✓" : "○"}</span> {check.label}
                          </li>
                        ))}
                      </ul>
                    </HelpHint>
                  </div>
                  <input 
                    type="text" 
                    value={values.consoleUser} 
                    placeholder="username"
                    onChange={(event) => setField("consoleUser", event.target.value)}
                    minLength={isHuawei ? 6 : undefined}
                    maxLength={32}
                    required
                  />
                </div>
              )}
              {consoleUserRequired && (
                <div className="field">
                  <div className="field-label-with-hint">
                    <label>Device CLI Password *</label>
                    <PasswordPolicyHint
                      checks={consolePasswordChecks}
                      invalid={Boolean(values.consolePass) && !consolePasswordValid}
                    />
                  </div>
                  <input
                    type="password"
                    value={values.consolePass}
                    placeholder="password"
                    onChange={(event) => setField("consolePass", event.target.value)}
                    required
                  />
                </div>
              )}
              

              {isExisting && (
                <div className="field">
                  <div className="field-label-with-hint">
                    <label>Add a new local administrator user</label>
                    <HelpHint label="Explain local administrator creation">
                      Use a username that does not already exist on the device. The system cannot check the device before it connects. If the username already exists, these commands can change that account&apos;s password and administrator privileges.
                    </HelpHint>
                  </div>
                  <div className="toggle-switch-container">
                    <input
                      type="checkbox"
                      id="cli-add-local-admin"
                      checked={values.addLocalAdmin}
                      onChange={(event) => handleLocalAdminToggle(event.target.checked)}
                    />
                    <label className="toggleSwitch" htmlFor="cli-add-local-admin"></label>
                  </div>
                </div>
              )}
              {localAdminEnabled && (
                <>
                  <div className="field">
                    <div className="field-label-with-hint">
                      <label>Local Administrator Username *</label>
                      <HelpHint label="Show local administrator username requirements">
                        Use 6-32 characters. Start with a letter or number. Only letters, numbers, period (.), underscore (_), and hyphen (-) are allowed.
                      </HelpHint>
                    </div>
                    <input
                      type="text"
                      value={values.localAdminUser}
                      placeholder="username"
                      autoComplete="off"
                      minLength={6}
                      maxLength={32}
                      onChange={(event) => setField("localAdminUser", event.target.value)}
                      required
                    />
                  </div>
                  <div className="field">
                    <div className="field-label-with-hint">
                      <label>Password *</label>
                      <PasswordPolicyHint checks={localAdminPasswordChecks} invalid={localAdminPasswordInvalid} />
                    </div>
                    <input
                      type="password"
                      value={values.localAdminPass}
                      placeholder="password"
                      autoComplete="new-password"
                      onChange={(event) => setField("localAdminPass", event.target.value)}
                      required
                    />
                  </div>
                </>
              )}

              <div className="field">
                <label>Cloud Username</label>
                <input type="text" value={adminUsername || "Loading..."} disabled />
              </div>

              <div className="field">
                <label htmlFor="cli-server-ip">
                  Cloud Server IP
                </label>
                <IPv4Input
                  id="cli-server-ip"
                  label="Cloud Server IP"
                  value={values.cloudServerIp}
                  onChange={(value) => setField("cloudServerIp", value)}
                  disabled={serverIpAutoFilled}
                  required
                />
              </div>

              <div className="field">
                <label htmlFor="cli-server-port">Cloud Server Port</label>
                <input
                  id="cli-server-port"
                  type="number"
                  value={values.cloudServerPort}
                  onChange={(event) => setField("cloudServerPort", event.target.value)}
                  required
                  disabled
                />
              </div>

              <div className="modal-actions">
                <button type="submit" className="btn btn-primary" disabled={submitting || loadingRegenerationTarget}>
                  {submitting
                    ? "Generating..."
                    : loadingRegenerationTarget
                      ? "Loading..."
                      : pendingDevice || regenerationTarget
                        ? "Regenerate CLI"
                        : "Generate"}
                </button>
              </div>
            </form>
          </div>

          <div className="cli-generator-output-panel detail-panel">
            <h2>CLI Output</h2>

            {pendingDevice && (
              <div className="cli-generator-enrollment-notice" role="status">
                <div className="cli-generator-enrollment-header">
                  <div>
                    <div className="cli-generator-enrollment-title">
                      {pendingDevice.name && <strong>{pendingDevice.name}</strong>}
                      <span className={`badge ${enrollmentStatusClass}`}>{enrollmentStatusText}</span>
                    </div>
                    <div className="cli-generator-enrollment-meta">
                      {values.vendor.toUpperCase()} · {values.deviceRole === "switch" ? "Switch" : "Router / firewall"} · {formatCreatedAt(pendingDevice.createdAt)}
                    </div>
                  </div>
                  <button type="button" className="btn btn-ghost cli-generator-enroll-another" onClick={handleGenerateAnother}>
                    + Enroll another device
                  </button>
                </div>
                <div className="cli-generator-enrollment-progress" aria-label="Enrollment progress">
                  <div className={`enrollment-progress-step ${enrollmentStep >= 1 ? "is-complete" : ""}`}>
                    <span className="enrollment-progress-icon">✓</span><span>Slot created</span>
                  </div>
                  <span className={`enrollment-progress-line ${enrollmentStep >= 2 ? "is-complete" : ""}`} />
                  <div className={`enrollment-progress-step ${enrollmentStep >= 2 ? "is-current" : ""}`}>
                    <span className="enrollment-progress-icon">›</span><span>Run CLI on device</span>
                  </div>
                  <span className={`enrollment-progress-line ${enrollmentStep >= 3 ? "is-complete" : ""}`} />
                  <div className={`enrollment-progress-step ${enrollmentStep >= 3 ? "is-current" : ""}`}>
                    <span className="enrollment-progress-icon">⌁</span><span>Device calls home</span>
                  </div>
                </div>
                <div className="cli-generator-enrollment-message">
                  <span aria-hidden="true">♙</span>
                  <span>This CLI is shown once. Changing the form and regenerating keeps the same device and SSH key, but revokes any earlier CLI. The newest version is active.</span>
                </div>
                {bootstrapExpiresAt && (
                  <div
                    className={`cli-generator-enrollment-message ${
                      bootstrapRemainingSeconds !== null && bootstrapRemainingSeconds <= 0
                        ? "cli-generator-bootstrap-expired"
                        : "cli-generator-bootstrap-active"
                    }`}
                    style={
                      bootstrapRemainingSeconds !== null && bootstrapRemainingSeconds <= 0
                        ? {
                            background: "rgba(239, 68, 68, 0.15)",
                            border: "1px solid rgba(239, 68, 68, 0.4)",
                            color: "#fca5a5",
                            marginTop: "8px",
                          }
                        : {
                            background: "var(--warning-dim, rgba(245, 158, 11, 0.15))",
                            border: "1px solid var(--warning, rgba(245, 158, 11, 0.4))",
                            color: "var(--warning, #fbbf24)",
                            marginTop: "8px",
                          }
                    }
                    role="alert"
                  >
                    <span aria-hidden="true">
                      {bootstrapRemainingSeconds !== null && bootstrapRemainingSeconds <= 0 ? "⚠️" : "⏱️"}
                    </span>
                    <span>
                      {bootstrapRemainingSeconds !== null && bootstrapRemainingSeconds <= 0
                        ? "Download link has expired — paste will fail. Click Regenerate to create a new link."
                        : `Download link expires in ${formatBootstrapRemaining(bootstrapRemainingSeconds)} — paste the CLI onto the device before it expires, or click Regenerate.`}
                    </span>
                  </div>
                )}
              </div>
            )}

            {renderedSteps.length > 0 ? (
              <>
                <p className="cli-generator-steps-intro">
                  Copy each step in order and paste it into the device console. Wait for one step to finish before pasting the next.
                </p>
                {renderedSteps.map((step, index) => {
                  const stepId = step.id || `step-${index}`;
                  const isLoadStep = Boolean(step.can_view_payload && boilerplateText);
                  const hint = cliStepHint(step.id);
                  return (
                    <div key={stepId} className="cli-generator-segment">
                      <div className="cli-generator-segment-header">
                        <div className="cli-generator-step-title">
                          <span className="cli-generator-step-number" aria-label={`Step ${index + 1}`}>{index + 1}</span>
                          <div>
                            <h3>{step.label || <>Part {index + 1}</>}</h3>
                            {hint && <p className="cli-generator-step-hint">{hint}</p>}
                          </div>
                        </div>
                        <div className="cli-generator-segment-actions">
                          {isLoadStep && (
                            <button type="button" className="btn btn-inspect" onClick={() => setShowBoilerplate(true)}>
                              View Configuration Payload
                            </button>
                          )}
                          <button type="button" className="btn btn-primary" onClick={() => handleCopySegment(stepId, step.commands)}>
                            {copiedSegments[stepId] ? "Copied" : "Copy"}
                          </button>
                        </div>
                      </div>
                      <AutoSizeTextarea readOnly value={step.commands} onClick={(event) => event.target.select()} />
                      {step.requires_manual_commit_before_next && (
                        <div className="cli-generator-step-notice">
                          ⚠️ {step.warning_message || "Review and commit the initial network configuration before downloading the bootstrap configuration. The system does not commit configuration automatically."}
                        </div>
                      )}
                    </div>
                  );
                })}
                {doneCard}
              </>
            ) : cliText ? (
              <>
                <div className="cli-generator-segment-header">
                  <p className="cli-generator-step-hint">
                    Copy all commands and paste them into the device console. The device then connects to the server.
                  </p>
                  <button type="button" className="btn btn-primary" onClick={handleCopy}>
                    {copied ? "Copied" : "Copy"}
                  </button>
                </div>
                <AutoSizeTextarea readOnly value={cliText} onClick={(event) => event.target.select()} />
                {doneCard}
              </>
            ) : (
              <div className="config-placeholder">Fill in the configuration on the left and click Generate to produce CLI commands.</div>
            )}

            {showBoilerplate && boilerplateText && (
              <div className="modal-overlay" onClick={() => setShowBoilerplate(false)}>
                <div
                  className="cli-generator-boilerplate-modal"
                  onClick={(event) => event.stopPropagation()}
                >
                  <div className="modal-header">
                    <div>
                      <h2>Config Loaded Automatically by Device (No copy-paste needed)</h2>
                       <p className="field-hint">
                        This configuration is fetched automatically by the device in the final step. Shown here for verification.
                      </p>
                    </div>
                    <button
                      type="button"
                      className="modal-close"
                      onClick={() => setShowBoilerplate(false)}
                      aria-label="Close"
                    >
                      &times;
                    </button>
                  </div>
                  <div className="cli-generator-segment-header">
                    <h3>Configuration payload</h3>
                    <button type="button" className="btn btn-primary" onClick={handleCopyBoilerplate}>
                      {copiedBoilerplate ? "Copied" : "Copy"}
                    </button>
                  </div>
                  <AutoSizeTextarea readOnly value={boilerplateText} onClick={(event) => event.target.select()} />
                </div>
              </div>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}
