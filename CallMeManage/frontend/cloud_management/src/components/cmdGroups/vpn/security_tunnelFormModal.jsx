import DismissibleError from "../../DismissibleError";
import { useEffect, useState } from "react";
import { runDeviceCommand, validateDeviceCommand } from "../../../api/api_devices";
import getDeviceInformation from "../../../hooks/getDeviceInformation";
import { isOptionHidden, useDeviceCapability } from "../../../hooks/deviceCapability";
import { normalizeSubnet } from "../../../utils/normalizeSubnet";
import IPv4Input from "../../common/IPv4Input";
import { validateIPv4Input } from "../../../utils/ipv4Input";
import { parseSecurityProfiles } from "./parseSecurityProfiles";
import { getWanZoneInterfaces } from "../../../utils/wanZoneInterfaces";
import { isJuniperSelectableInterfaceUnit } from "../../../utils/interfaceKind.js";

// (bug 91) เคยมี sleep 2500ms คั่นระหว่าง remove กับ create ตอนแก้ไข เพราะยิงติดกัน
// แล้วเจอ rpc-error "in-use" - ตอนนี้ไม่มีขั้น remove แล้ว (ใช้ replace ใน RPC เดียว)
// อาการนั้นจึงหมดไปพร้อมกับต้นเหตุ ไม่ต้องหน่วงเวลาเดาอีก

// Tunnel IP กรอกเป็น "ip/prefix" ช่องเดียวผ่าน IPv4Input (mode cidr) ตัวเดียวกับหน้า
// Interfaces - Cisco's create_security_tunnel ต้องการ subnetMask (dotted decimal) ตรงๆ
// ไปที่ <mask> ส่วน Juniper's ต้องการ prefix length ดิบไปที่ IPv4Interface("ip/prefix")
// normalizeSubnet แปลง prefix -> subnet mask ให้ตอน submit
//
// เดิมเป็น text box เปล่าที่ตรวจแค่ "มี / และ normalizeSubnet แปลงได้" - octet อย่าง
// 999.1.1.1 หรือ host ที่ชนกับ network/broadcast ของวงตัวเอง (เช่น 10.10.10.0/30) ผ่าน
// ฟอร์มไปถึงอุปกรณ์ได้หมด แล้วไปตายที่ validate_host_in_network (bug 70) - ตอนนี้
// hostOnly ของตัวตรวจกลางจับให้ตั้งแต่ในฟอร์ม

// โหมด Edit: pre-fill จาก editTarget (แถวที่เลือกจาก security_tunnel.jsx -
// {name, type, tunIp, tunMask, source, destination, securityProfile}) - ต่างจาก
// Security Profile/ZBF ตรงที่ข้อมูลนี้ครบทุกฟิลด์จริง (parseSecurityTunnels
// อ่านได้ครบ ไม่มีข้อจำกัดเรื่อง pre-fill เลย) - เลขลำดับ Tunnel/st0 unit/gr- slot
// ใช้เลขเดิมเสมอตอน edit (ไม่ให้เปลี่ยนเลข ไม่มี UI ให้เปลี่ยนอยู่แล้วแม้แต่ตอน
// สร้าง) - **greWanIp ไม่ pre-fill** สำหรับ Juniper GRE (editTarget.source เป็น
// tunnel source IP ที่ resolve มาแล้วตอนสร้าง ไม่ใช่ชื่อ interface - ไม่มีทาง
// derive ชื่อ interface กลับจาก IP ได้แม่นยำ 100% ถ้า IP นั้นถูกย้ายไป interface
// อื่นทีหลัง ให้ user เลือก "ขา Outbound" ใหม่เองปลอดภัยกว่า)
function buildTunAddress(tunIp, tunMask) {
  if (!tunIp || !tunMask) return "";
  const subnet = normalizeSubnet(tunMask);
  return subnet ? `${tunIp}/${subnet.prefix}` : "";
}

function buildInitialValues(mode, editTarget, isJuniper) {
  if (mode !== "edit" || !editTarget) {
    return { tunnelType: "ipsec", securityProfile: "", tunAddress: "", remoteIp: "", wanInterface: "", greInterface: "", mtu: "" };
  }
  const isGre = editTarget.type === "GRE";
  return {
    tunnelType: isGre ? "gre" : "ipsec",
    securityProfile: editTarget.securityProfile || "",
    // Cisco คืน tunMask มาเป็น dotted mask ส่วน Junos คืนเป็น prefix อยู่แล้ว - IPv4Input
    // โหมด cidr รับเฉพาะ prefix จึง normalize ให้เป็นรูปเดียวกันก่อนเสมอ
    tunAddress: buildTunAddress(editTarget.tunIp, editTarget.tunMask),
    remoteIp: editTarget.destination || "",
    wanInterface: isJuniper && isGre ? "" : editTarget.source || "",
    // gr-0/0/0.0 -> "gr-0/0/0" (ตัด unit suffix ".0" ท้ายออก - ตรงกับ option
    // value ใน dropdown ที่เป็นชื่อ interface เปล่าไม่มี unit)
    greInterface: isGre ? editTarget.name.replace(/\.\d+$/, "") : "",
    // mtu อยู่ระดับ physical interface เดียวกันทั้ง st0/gr-*/Tunnel (ดู
    // security_tunnel.jsx's parseSecurityTunnels/parseJuniperSecurityTunnels)
    mtu: editTarget.mtu ? String(editTarget.mtu) : "",
  };
}

// สร้าง Tunnel interface ผ่าน create_security_tunnel ตัวเดียว - Cisco: IPsec
// หรือ GRE เลือกได้จาก dropdown เดียว, เลขลำดับ Tunnel (Tunnel0/Tunnel1/...)
// ให้ระบบคำนวณเองจาก get_interface_list (หาตัวเลขที่ว่างถัดไป)
//
// Juniper: รองรับทั้ง IPsec (route-based VPN ผ่าน st0) และ GRE (gr-* interface
// จริง - ยืนยันจริงผ่าน CLI/commit แล้วว่ามี schema `tunnel/source`+
// `tunnel/destination` ตรงๆ ใต้ unit ของ gr- interface) **ต่างจาก IPsec สำคัญๆ**:
// gr- เป็น physical/pseudo interface ที่มีจำนวนจำกัดบนอุปกรณ์จริง (ไม่ใช่ unit
// ไม่จำกัดแบบ st0) เลยให้ user **เลือกจาก interface ที่มีอยู่จริง** แทนคำนวณเลข
// ถัดไปเอง (กรอง gr- ที่ถูกใช้เป็น GRE tunnel อื่นไปแล้วออก) และ "ขา Outbound"
// สำหรับ GRE หมายถึง**tunnel source IP** (Junos ต้องการ IP address ตรงๆ ต่างจาก
// Cisco ที่ใช้ชื่อ interface ตรงๆ ได้เลย) เลย resolve จาก interface ที่เลือกผ่าน
// get_ip_interface_brief ก่อนส่งเป็น wan_interface param ให้ backend
export default function SecurityTunnelFormModal({ devId, vendor, mode = "create", editTarget = null, allTunnels = null, onClose, onSaved }) {
  const isJuniper = vendor === "juniper";
  const isEdit = mode === "edit" && !!editTarget;
  // (dynamic feature) อุปกรณ์ที่ทำ IPsec แบบ tunnel interface ไม่ได้ (c9000 · มีผลเฉพาะตอนเปิดการกรอง) เหลือ GRE
  // ให้เลือกอย่างเดียว ยกเว้นกำลังแก้ IPsec tunnel ที่มีอยู่แล้วบนอุปกรณ์
  const { hiddenOptions } = useDeviceCapability();
  const ipsecSelectable =
    !isOptionHidden(hiddenOptions, "create_security_tunnel", "tunnel_type", "ipsec") || (isEdit && editTarget.type !== "GRE");
  const [values, setValues] = useState(() => {
    const initial = buildInitialValues(mode, editTarget, isJuniper);
    return !ipsecSelectable && initial.tunnelType === "ipsec" ? { ...initial, tunnelType: "gre" } : initial;
  });
  // ข้อมูลความสามารถอาจโหลดเสร็จหลังเปิดฟอร์ม - เปลี่ยนเป็น GRE ให้เองถ้า IPsec เลือกไม่ได้แล้ว
  useEffect(() => {
    if (ipsecSelectable) return;
    setValues((prev) => (prev.tunnelType === "ipsec" ? { ...prev, tunnelType: "gre" } : prev));
  }, [ipsecSelectable]);
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const { data: ifListData, loading: ifListLoading } = getDeviceInformation(devId, "get_interface_list");
  const allInterfaceNames = ifListData?.normalized ? ifListData.result.map((row) => row.name).filter(Boolean) : [];
  // ขา WAN ออกไม่ควรเลือก Tunnel interface เอง (ไม่มี tunnel ซ้อน tunnel)
  const wanOptions = allInterfaceNames.filter(
    (name) => (
      (!isJuniper || isJuniperSelectableInterfaceUnit(name))
      && !/^Tunnel\d+$/i.test(name)
      && !/^st0\./i.test(name)
      && !/^gr-/i.test(name)
    )
  );

  // user ขอ: default "ขา Outbound" เป็น interface ที่เป็นสมาชิกของ zone "WAN"
  // ให้เองก่อนเลย ทั้ง Cisco และ Juniper - Cisco ต้อง join กับ
  // get_switchport_information เพิ่ม (zone-member เป็น leaf ต่อ interface ไม่ใช่
  // list ใต้ zone แบบ Junos - ดู getWanZoneInterfaces/parseCiscoZoneMembership)
  // ส่วน Juniper อ่านจาก security-zone/interfaces ตรงๆ พอ - wanInterface ไม่ถูก
  // pre-fill ตอน edit สำหรับ GRE/Cisco บาง case (ดู buildInitialValues) เช็คแค่
  // "ยังไม่มีค่า" ก็พอครอบคลุมทั้ง create และ edit ที่ยังว่างอยู่
  // Juniper + GRE เท่านั้น: resolve ชื่อ interface ที่เลือกใน "ขา Outbound" เป็น
  // IP จริง (get_interface_list ให้แค่ชื่อ ไม่มี IP - ต้อง query เพิ่ม)
  const { data: ifBriefData, loading: ifBriefLoading } = getDeviceInformation(
    devId,
    isJuniper && values.tunnelType === "gre" ? "get_ip_interface_brief" : null
  );
  const ifBriefRows = ifBriefData?.normalized ? ifBriefData.result : [];

  // (เคส C ซ้ำรอย) Junos GRE เก็บ tunnel source เป็น **IP** ไม่ใช่ชื่อ interface ฟอร์มจึง
  // pre-fill ช่อง "ขา Outbound" จาก editTarget.source ตรง ๆ ไม่ได้ ของเดิมเลยปล่อยว่างแล้ว
  // ให้ตัวเดา zone WAN ด้านล่างเติมให้ ซึ่งแปลว่าผู้ใช้ที่เข้ามาแก้แค่ MTU กด Save ก็ย้าย
  // tunnel source ไปเป็น IP ของขาที่ระบบเดาให้ (create ใช้ replace ทั้ง unit) โดยหน้าจอ
  // ไม่เคยบอกว่าของจริงคือขาไหน - บั๊กเดียวกับ WAN Interface ของหน้า Security Profile
  //
  // ทางแก้: derive ชื่อกลับจาก IP ด้วย get_ip_interface_brief ที่ฟอร์มนี้ดึงมาอยู่แล้ว
  // (คอมเมนต์เดิมบอกว่า "ไม่มีทาง derive กลับได้แม่นยำ 100%" ซึ่งจริงเฉพาะกรณีที่ IP ถูก
  // ย้ายไป interface อื่นไปแล้ว - กรณีนั้นจับได้และบอกผู้ใช้ตรง ๆ ดีกว่าเดาเงียบ ๆ ทุกครั้ง)
  const isJuniperGreEditing = isEdit && isJuniper && values.tunnelType === "gre";
  const greSourceIp = isJuniperGreEditing ? editTarget?.source || "" : "";
  const greSourceInterface = greSourceIp
    ? ifBriefRows.find((row) => row.ip === greSourceIp)?.name || ""
    : "";
  // ยังอ่าน interface brief ไม่เสร็จ = ยังตอบไม่ได้ว่า IP นั้นคือขาไหน ห้ามให้ตัวเดาเติมทับ
  const awaitingGreSource = Boolean(greSourceIp) && !ifBriefData?.normalized;
  // อ่านเสร็จแล้วแต่ไม่มี interface ไหนถือ IP นั้นอยู่ (ถูกย้าย/ถูกลบไปแล้ว) - เคสนี้เดาให้ได้
  // แต่ต้องบอกผู้ใช้ว่าของเดิมคือ IP อะไร ไม่ใช่เปลี่ยนให้เงียบ ๆ
  useEffect(() => {
    if (!greSourceInterface || values.wanInterface) return;
    setField("wanInterface", greSourceInterface);
  }, [greSourceInterface, values.wanInterface]);

  const { data: zoneData } = getDeviceInformation(devId, "get_security_zone_information");
  const { data: switchportData } = getDeviceInformation(devId, !isJuniper ? "get_switchport_information" : null);
  const wanZoneInterfaces = getWanZoneInterfaces({ vendor, zoneResult: zoneData, switchportResult: switchportData });
  useEffect(() => {
    // อย่าเดาระหว่างที่ยังรอคำตอบว่า tunnel source ของจริงคือขาไหน และอย่าเดาทับค่าที่
    // resolve ได้แล้ว (2 effect นี้แข่งกันได้ - zone data มักมาถึงก่อน interface brief)
    if (values.wanInterface || awaitingGreSource || greSourceInterface) return;
    const match = wanZoneInterfaces.find((name) => wanOptions.includes(name));
    if (match) setField("wanInterface", match);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [values.wanInterface, awaitingGreSource, greSourceInterface, wanZoneInterfaces.join(","), wanOptions.join(",")]);

  // gr- interface ที่มีอยู่จริงบนอุปกรณ์ (bare ไม่มี unit) กรองตัวที่ถูกใช้เป็น
  // GRE tunnel อื่นไปแล้วออก (ยกเว้นตัวที่กำลังแก้ไขอยู่ตอน edit)
  // allTunnels เป็น null ได้ = หน้าแม่ยังตอบไม่ได้ว่ามี tunnel อะไรอยู่บ้าง ต้องแยกให้ออก
  // จาก [] ที่แปลว่า "อ่านสำเร็จแล้วและไม่มีเลย" - ความต่างนี้ชี้ขาดตอนคำนวณเลขลำดับถัดไป
  const knownTunnels = Array.isArray(allTunnels) ? allTunnels : [];
  const usedGreInterfaces = new Set(
    knownTunnels
      .filter((t) => t.type === "GRE" && !(isEdit && t.name === editTarget?.name))
      .map((t) => t.name.replace(/\.\d+$/, ""))
  );
  const greInterfaceOptions = allInterfaceNames.filter((name) => /^gr-/i.test(name) && !usedGreInterfaces.has(name));

  // เลขลำดับ Tunnel/st0 unit ถัดไปที่ยังไม่ถูกใช้ - GRE ไม่ใช้เลขอัตโนมัติ (เลือก
  // interface ตรง ๆ ด้านบน)
  //
  // **รวมทุกแหล่งที่รู้เสมอ ไม่พึ่งแหล่งเดียว** - เดิม Cisco นับจาก get_interface_list
  // อย่างเดียวและ Juniper นับจากตารางอย่างเดียว ซึ่งพลาดได้ทั้งคู่:
  //   Cisco  - ถ้า get_interface_list ล้มเหลว ลิสต์กลายเป็นว่าง -> เลขถัดไป = 0 ->
  //            create_security_tunnel ใช้ nc:operation="replace" -> **ทับ Tunnel0 ที่
  //            ใช้งานอยู่ทั้ง node** โดยไม่มี error ไม่มีคำเตือน (ตอนนั้น wanOptions ก็ว่าง
  //            ฟอร์มจึงสลับเป็นช่องพิมพ์ชื่อ interface เอง = ยังกดสร้างได้ตามปกติ)
  //   Juniper - ตารางนับเฉพาะ st0 unit ที่มี security/ipsec/vpn ผูกอยู่ (parser เดินจาก
  //            vpn list) unit ที่มีอยู่จริงแต่ไม่มี vpn ผูก (vpn ถูกลบไปก่อน/ตั้งค้างจาก
  //            CLI) จึงหายไปจากการนับ แล้วเลขถัดไปไปชนกับมันได้
  // interface list มี "TunnelN"/"st0.N" ทั้งคู่อยู่แล้ว (Junos terse คืน logical
  // interface ด้วย) เอามารวมกับตารางจึงครอบคลุมกว่าทั้งสองแบบ
  const tunnelNumberPattern = isJuniper ? /^st0\.(\d+)$/i : /^Tunnel(\d+)$/i;
  const tunnelNumbersIn = (names) =>
    names
      .map((name) => tunnelNumberPattern.exec(name || ""))
      .filter(Boolean)
      .map((match) => Number(match[1]));
  const existingTunnelNumbers = [
    ...tunnelNumbersIn(allInterfaceNames),
    ...tunnelNumbersIn(knownTunnels.map((t) => t.name)),
  ];
  const nextTunnelNumber = existingTunnelNumbers.length > 0 ? Math.max(...existingTunnelNumbers) + 1 : 0;

  // **ว่างเพราะไม่มี** กับ **ว่างเพราะอ่านไม่ได้** ให้เลขเดียวกัน (0) แต่ผลต่างกันคนละเรื่อง
  // ถ้ายังไม่รู้ว่าเลขไหนถูกใช้อยู่ ห้ามสร้างใหม่เด็ดขาด - รอข้อมูลหรือให้ผู้ใช้กด refresh
  // ดีกว่าเขียนทับของที่ใช้งานอยู่ (โหมดแก้ไขไม่ต้องใช้เลขใหม่ จึงไม่ถูกบล็อก และ GRE ของ
  // Junos เลือก interface เองอยู่แล้ว)
  const tunnelNumbersKnown = Boolean(ifListData?.normalized) && Array.isArray(allTunnels);

  const { data: profileData, loading: profileLoading } = getDeviceInformation(
    devId,
    "get_security_profile_information"
  );
  const securityProfiles = profileData?.normalized ? parseSecurityProfiles(profileData.result) : [];
  const canPickProfile = Array.isArray(securityProfiles) && securityProfiles.length > 0;

  function setField(name, value) {
    setValues((prev) => ({ ...prev, [name]: value }));
  }

  const isJuniperGre = isJuniper && values.tunnelType === "gre";
  // สร้างใหม่แบบที่ระบบต้องเลือกเลขให้เอง (Cisco ทุกชนิด + Junos IPsec) - Junos GRE
  // ผู้ใช้เลือก gr- interface เองจึงไม่ต้องใช้เลข และโหมดแก้ไขใช้เลขเดิมเสมอ
  const blockedByUnknownNumbers = !isEdit && !isJuniperGre && !tunnelNumbersKnown;

  async function handleSubmit(event) {
    event.preventDefault();
    setError("");

    // ด่านที่สอง - ปุ่มถูกปิดไว้แล้วเมื่อยังไม่รู้เลขที่ถูกใช้อยู่ กันไว้อีกชั้นเพราะผลของ
    // การปล่อยผ่านคือเขียนทับ tunnel ที่ใช้งานอยู่ (create ใช้ replace) ไม่ใช่แค่สร้างพลาด
    if (blockedByUnknownNumbers) {
      return setError("Unable to read device interface list, cannot determine which Tunnel numbers are in use - click refresh and try again");
    }
    if (values.tunnelType === "ipsec" && !values.securityProfile) {
      return setError("Please select Security Profile (create one in Security Profile page first if none exists)");
    }
    if (isJuniperGre && !isEdit && !values.greInterface) {
      return setError("Please select GRE Interface (an existing gr-x/x/x on device)");
    }
    if (!values.wanInterface) return setError(isJuniperGre ? "Please select interface to use its IP as Tunnel Source" : "Please select Outbound Interface (Via)");

    const remote = validateIPv4Input(values.remoteIp, { mode: "address" });
    if (!remote.valid) return setError("Please enter a valid Destination Public IP, e.g. 203.0.113.5");
    const remoteIp = remote.value;

    // hostOnly = ห้ามเป็น network/broadcast ของวงตัวเอง (ยกเว้น /31-/32 ที่ไม่มีแนวคิดนี้)
    // ตรงกับที่ validate_host_in_network ของ translator บังคับอยู่แล้ว - จับตั้งแต่ในฟอร์ม
    // ดีกว่าปล่อยให้ไปตายที่อุปกรณ์แล้ว tunnel หายทั้งตัว (bug 70)
    const tun = validateIPv4Input(values.tunAddress, { mode: "cidr", hostOnly: true });
    if (!tun.valid) {
      return setError("Please enter a valid Tunnel IP with prefix, e.g. 10.10.10.1/30 (must be host address, not network/broadcast of the subnet)");
    }
    const tunAddress = { ip: tun.address, prefix: tun.prefix, mask: normalizeSubnet(String(tun.prefix)).subnetMask };

    let wanInterfaceParam = values.wanInterface;
    if (isJuniperGre) {
      const matched = ifBriefRows.find((row) => row.name === values.wanInterface);
      if (!matched?.ip) {
        return setError(`Cannot find IP for ${values.wanInterface} - please configure an IP on this interface first (in Interfaces page)`);
      }
      wanInterfaceParam = matched.ip;
    }

    // แก้ไข tunnel ที่มีอยู่แล้ว: ใช้เลขลำดับ Tunnel/st0 unit/gr- interface เดิม
    // เสมอ (ไม่ต้องคำนวณเลขใหม่ - ไม่มี UI ให้เปลี่ยนเลขอยู่แล้วแม้แต่ตอนสร้าง)
    const interfaceNumber = isEdit
      ? isJuniper
        ? isJuniperGre
          ? editTarget.name.replace(/^gr-/, "").replace(/\.\d+$/, "")
          : editTarget.name.split(".").pop()
        : editTarget.name.replace(/^Tunnel/i, "")
      : isJuniperGre
        ? values.greInterface.replace(/^gr-/, "")
        : String(nextTunnelNumber);

    const params = {
      tunnel_type: values.tunnelType,
      interface_number: interfaceNumber,
      tun_ip: tunAddress.ip,
      tun_subnet: isJuniper ? String(tunAddress.prefix) : tunAddress.mask,
      wan_interface: wanInterfaceParam,
      remote_ip: remoteIp,
      // ค่าว่าง -> undefined (JSON.stringify ตัดคีย์นี้ทิ้งเอง) - ไม่ต้องมี guard
      // แยกยี่ห้อ/tunnel type เพราะ create_security_tunnel รองรับ mtu ครบทั้ง
      // Cisco/Juniper และทั้ง ipsec/gre แล้ว
      mtu: values.mtu ? Number(values.mtu) : undefined,
    };
    if (values.tunnelType === "ipsec") {
      params.ipsec_profile = values.securityProfile;
    }
    // Junos เก็บ Destination Public IP ไว้ที่ IKE gateway/address (leaf-list)
    // ไม่ได้อยู่ใต้ st0 หรือ VPN โดยตรง ระบุค่าเดิมให้ translator ลบเฉพาะ peer
    // ตัวเดิมและเพิ่มตัวใหม่ใน edit-config เดียวกัน โดยไม่ replace gateway ทั้งก้อน
    // ซึ่งอาจทำค่า Brownfield อื่นหาย การเปลี่ยน Profile จะชี้ไป gateway คนละตัว
    // จึงห้ามนำ address ของ Profile เดิมไปลบจาก Profile ใหม่
    if (
      isEdit
      && isJuniper
      && !isJuniperGre
      && values.securityProfile === editTarget.securityProfile
      && remoteIp !== editTarget.destination
    ) {
      params.old_remote_ip = editTarget.destination;
    }
    // Junos brownfield: แก้ object เดิมด้วยชื่อจริงที่ parser อ่านจากอุปกรณ์ ไม่ derive ชื่อใหม่
    if (isEdit && isJuniper && editTarget.real) {
      if (isJuniperGre) {
        params.gre_interface = editTarget.real.interfaceName;
        params.gre_unit = editTarget.real.unitName;
      } else {
        params.vpn_name = editTarget.real.vpnName;
        params.bind_interface = editTarget.real.bindInterface;
        // ถ้ายังใช้ Security Profile เดิม ต้องคงชื่อ brownfield จริงไว้ แต่ถ้าผู้ใช้เลือก
        // Profile ใหม่ ให้ translator derive gateway/policy ของ Profile ใหม่นั้นตามปกติ
        if (values.securityProfile === editTarget.securityProfile) {
          params.gateway_name = editTarget.real.gatewayName;
          params.ipsec_policy_name = editTarget.real.ipsecPolicyName;
        }
      }
    }

    setSubmitting(true);
    try {
      // (ปัญหาที่ 2 ขั้น B0) ตรวจค่าที่ผู้ใช้กรอกให้ผ่านก่อนลงมือจริงเสมอ - ตอนนี้ไม่มี
      // ขั้นลบแล้วก็จริง แต่ replace ที่ค่าผิดก็ทำให้ tunnel ที่ใช้งานอยู่พังได้เหมือนกัน
      await validateDeviceCommand(devId, "create_security_tunnel", params);

      // (bug 91/79 · ระลอก C3) เดิมตอนแก้ไขต้อง "รื้อ interface ทิ้งก่อนแล้วค่อยสร้างใหม่"
      // ซึ่งพังทั้ง 2 ยี่ห้อทันทีที่มีใครอ้าง interface นั้นอยู่
      //
      //   Cisco:   illegal reference ... disable-interface/Tunnel[name='0']/name
      //            (OSPF ถือ `no passive-interface Tunnel0` อยู่)
      //   Juniper: 'remove_tunnel_interface': Interface st0.0 must be configured under interfaces
      //            (security/ipsec/vpn ยัง bind-interface มาที่ st0.0 อยู่)
      //
      // ทั้งที่ผู้ใช้แค่อยากเพิ่ม MTU และทำผ่าน CLI ตรง ๆ ได้ไม่มีปัญหาเลย
      // ตอนนี้ create_security_tunnel ใช้ nc:operation="replace" แล้ว node ไม่เคยหายไป
      // จาก config reference จึงไม่เคยขาด แต่ leaf เก่าที่ไม่ได้ส่งมารอบนี้ยังถูกล้าง
      // ให้เหมือนเดิม **1 action = 1 RPC = ประวัติ 1 แถว** ไม่ต้องมี delay คั่นอีกแล้ว
      await runDeviceCommand(devId, "create_security_tunnel", params);
      onSaved();
    } catch (err) {
      setError(err.detail || (isEdit ? "Failed to edit Tunnel" : "Failed to create Tunnel"));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form className="interface-configuration-form" onSubmit={handleSubmit}>
      {isEdit && <div className="command-output-title">Edit: {editTarget.name}</div>}
      {error && <DismissibleError message={error} onDismiss={() => setError("")} />}

      <div className="interface-configuration-form-field">
        <label className="data-label">Tunnel Type</label>
        <div
          className={`segmented-control${isEdit ? " locked-choice" : ""}`}
          title={isEdit ? "Tunnel type is fixed after creation" : undefined}
        >
          {ipsecSelectable && (
            <>
              <input
                type="radio"
                id="tunnel-type-ipsec"
                name="tunnel-type"
                value="ipsec"
                checked={values.tunnelType === "ipsec"}
                onChange={(event) => setField("tunnelType", event.target.value)}
                disabled={isEdit}
              />
              <label htmlFor="tunnel-type-ipsec">IPsec Tunnel</label>
            </>
          )}
          <input
            type="radio"
            id="tunnel-type-gre"
            name="tunnel-type"
            value="gre"
            checked={values.tunnelType === "gre"}
            onChange={(event) => setField("tunnelType", event.target.value)}
            disabled={isEdit}
          />
          <label htmlFor="tunnel-type-gre">GRE Tunnel</label>
        </div>
      </div>

      {values.tunnelType === "ipsec" && (
        <div className="interface-configuration-form-field">
          <label className="data-label">Security Profile</label>
          {profileLoading ? (
            <select disabled value="">
              <option value="">Loading Security Profiles...</option>
            </select>
          ) : canPickProfile ? (
            <select value={values.securityProfile} onChange={(event) => setField("securityProfile", event.target.value)}>
              <option value="" disabled>-- Select Security Profile --</option>
              {securityProfiles.map((profile) => (
                <option key={profile.fullName} value={profile.fullName}>
                  {profile.name}
                </option>
              ))}
            </select>
          ) : (
            <span>No Security Profile on this device - please create one in Security Profile page first</span>
          )}
        </div>
      )}

      {isJuniperGre && !isEdit && (
        <div className="interface-configuration-form-field">
          <label className="data-label">GRE Interface</label>
          {ifListLoading ? (
            <select disabled value="">
              <option value="">Loading interface list...</option>
            </select>
          ) : greInterfaceOptions.length > 0 ? (
            <select value={values.greInterface} onChange={(event) => setField("greInterface", event.target.value)}>
              <option value="" disabled>-- Select gr- interface --</option>
              {greInterfaceOptions.map((name) => (
                <option key={name} value={name}>
                  {name}
                </option>
              ))}
            </select>
          ) : (
            <span>No available gr- interface on this device (may already be in use by other GRE tunnels)</span>
          )}
        </div>
      )}

      <div className="interface-configuration-form-field">
        <label className="data-label">Tunnel IP / Subnet</label>
        <IPv4Input
          id="tunnel-ip"
          label="Tunnel IP"
          mode="cidr"
          hostOnly
          value={values.tunAddress}
          onChange={(value) => setField("tunAddress", value)}
          required
        />
      </div>

      <div className="interface-configuration-form-field">
        <label className="data-label">Destination Public IP</label>
        <IPv4Input
          id="tunnel-remote-ip"
          label="Destination Public IP"
          mode="address"
          value={values.remoteIp}
          onChange={(value) => setField("remoteIp", value)}
          required
        />
      </div>

      {/* MTU - optional, เหมือนหน้า Interfaces (ไม่กรอก = ใช้ default ของอุปกรณ์
          ต่อไป) แก้ปัญหา OSPF/routing protocol ที่วิ่งผ่าน tunnel เจอ MTU
          mismatch เหมือนกับ physical interface - Cisco เขียนเป็น ip mtu (สอดคล้อง
          กับหน้า Interfaces), Juniper เขียนเป็น physical mtu ของ st0/gr-* */}
      <div className="interface-configuration-form-field">
        <label className="data-label">MTU (bytes)</label>
        <input
          type="number"
          min="68"
          max="9216"
          placeholder="e.g. 1400 (Device default - optional)"
          value={values.mtu}
          onChange={(event) => setField("mtu", event.target.value)}
        />
      </div>

      <div className="interface-configuration-form-field">
        <label className="data-label">{isJuniperGre ? "Interface to use IP as Tunnel Source" : "Outbound Interface (Via)"}</label>
        {ifListLoading ? (
          <select disabled value="">
            <option value="">Loading interface list...</option>
          </select>
        ) : wanOptions.length > 0 ? (
          <select value={values.wanInterface} onChange={(event) => setField("wanInterface", event.target.value)}>
            <option value="" disabled>-- Select interface --</option>
            {wanOptions.map((name) => (
              <option key={name} value={name}>
                {name}
              </option>
            ))}
          </select>
        ) : (
          <input
            type="text"
            placeholder="e.g. GigabitEthernet2"
            value={values.wanInterface}
            onChange={(event) => setField("wanInterface", event.target.value)}
          />
        )}
      </div>

      <div className="interface-form-btn-container">
        <button
          type="submit"
          className="btn btn-primary"
          disabled={submitting || blockedByUnknownNumbers || (isJuniperGre && ifBriefLoading)}
        >
          {submitting ? "Sending..." : isJuniperGre && ifBriefLoading ? "Loading IP..." : isEdit ? "Save" : "OK"}
        </button>
        <button type="button" className="btn btn-ghost" onClick={onClose}>
          Cancel
        </button>
      </div>
    </form>
  );
}
