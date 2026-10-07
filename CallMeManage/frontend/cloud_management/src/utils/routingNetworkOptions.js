import { normalizeIP } from "./normalizeIP.js";
import { normalizeSubnet } from "./normalizeSubnet.js";
import { isJuniperRoutableUnit } from "./interfaceKind.js";

// ตรรกะของรายการติ๊กเลือก (โหมด Specific) และการเลือกให้เองของโหมด Any -
// ใช้ร่วมกันทั้งฟอร์ม RIP และ OSPF แยกออกมาจาก component เพื่อให้ทดสอบได้โดย
// ไม่ต้อง render React

export function ipToInt(ip) {
  const parts = (ip || "").trim().split(".");
  if (parts.length !== 4) return null;
  const octets = parts.map(Number);
  if (octets.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;
}

export function intToIp(value) {
  return [24, 16, 8, 0].map((shift) => (value >>> shift) & 0xff).join(".");
}

// RFC1918 - ใช้ตัดสินว่า interface นี้เป็น private (แจก RIP ได้) หรือ public
// (ขา WAN - ไม่ควรประกาศเข้า RIP ซึ่งเป็น interior routing protocol)
export function isPrivateIPv4(ip) {
  const value = ipToInt(ip);
  if (value === null) return false;
  return (
    (value >= ipToInt("10.0.0.0") && value <= ipToInt("10.255.255.255")) ||
    (value >= ipToInt("172.16.0.0") && value <= ipToInt("172.31.255.255")) ||
    (value >= ipToInt("192.168.0.0") && value <= ipToInt("192.168.255.255"))
  );
}

// network ที่ set_rip_routing ต้องการเป็น network address ตรงๆ (ไม่มี prefix -
// ipaddress.IPv4Address(network) ฝั่ง backend จะ parse ไม่ผ่านถ้ามี "/" ติดมา) -
// เลยต้องคำนวณ network address จาก host ip + prefix เอง (ip AND mask)
export function networkAddressOf(ip, prefix) {
  const ipInt = ipToInt(ip);
  if (ipInt === null) return null;
  const maskInt = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return intToIp((ipInt & maskInt) >>> 0);
}

// รายการตัวเลือกของ dropdown ติ๊กช่อง (รูปแบบเดียวกับ Interface Members ของ
// zoneInterfacesFormModal) - ต่างกันตามยี่ห้อตามที่ set_rip_routing ต้องการ:
//
// Juniper ผูก routing protocol ต่อ interface (RIP เขียนเป็น <neighbor>, OSPF เป็น <interface>)
// จึงติ๊กเป็น "ชื่อขา" ตรงๆ ส่วน Cisco ผูกต่อ network จึงให้ติ๊กเป็น "IP" ที่
// อุปกรณ์มีอยู่จริง แล้วส่ง network address ของ IP นั้นไปให้อุปกรณ์ - ค่าที่ส่ง
// เหมือนโหมด Any ทุกประการ ไม่ได้เปลี่ยนสัญญากับ backend เปลี่ยนแค่วิธีกรอกของ
// ผู้ใช้ จึงไม่ต้องโชว์ชื่อ interface ให้ Cisco ตามที่ผู้ใช้กำหนด
//
// value = ค่าที่ส่งเข้า set_rip_routing, label = สิ่งที่ผู้ใช้เห็น
//
// ค่าที่ตั้งไว้บนอุปกรณ์แล้วแต่หาคู่ในรายการปัจจุบันไม่เจอ (เช่น Cisco ย่อ
// network เป็น classful หรือขาที่ถูกลบไปแล้ว) ต้องยังโผล่และติ๊กค้างไว้เสมอ
// ไม่งั้นการกด Apply จะถอดมันออกจากอุปกรณ์เงียบๆ ทั้งที่ผู้ใช้ไม่เคยสั่ง
export function buildRoutingPickerOptions({ interfaceRows = [], selected = [], isJuniper = false } = {}) {
  const options = [];
  const seen = new Set();
  for (const row of interfaceRows) {
    let option = null;
    if (isJuniper) {
      // physical เปล่า ๆ ผูก RIP ไม่ได้ และ unit ภายในของ Junos (lo0/sp-/fxp0/
      // .32767) ก็ไม่ใช่ขาที่ผู้ใช้ตั้ง - เหลือเฉพาะขาที่ใช้งานได้จริง
      option = isJuniperRoutableUnit(row?.name) ? { value: row.name, label: row.name } : null;
    } else {
      const ip = normalizeIP(row?.ip);
      const subnet = normalizeSubnet(row?.subnet);
      const network = ip && ip !== "-" && subnet ? networkAddressOf(ip, subnet.prefix) : null;
      option = network ? { value: network, label: ip } : null;
    }
    if (!option || seen.has(option.value)) continue;
    seen.add(option.value);
    options.push(option);
  }
  for (const value of selected) {
    if (!value || seen.has(value)) continue;
    seen.add(value);
    options.push({ value, label: value, missing: true });
  }
  return options;
}


// โหมด Any: เลือกขาภายในให้เองทั้งหมด
//
// Juniper ส่งชื่อขา (RIP ของ Junos ผูกต่อ interface) ส่วน Cisco ส่ง network
// address ของ IP นั้น (RIP ของ IOS ผูกต่อ network) - เงื่อนไข "ภายใน" คือ
// RFC1918 ทั้งสองยี่ห้อ ขา public จึงไม่ถูกประกาศเข้า interior protocol
//
// Juniper ใช้ isJuniperRoutableUnit เป็นด่านเดียว **ไม่เช็ค subnet** เพราะ
// ค่าที่ส่งคือชื่อขา ไม่ได้ใช้ mask เลย (เดิมเช็ค `!subnet` ทั้งที่ไม่ได้ใช้
// ทำให้ Juniper ตกทุกแถวเสมอ: ตัวแปลงคำตอบอ่าน mask ของ Junos ไม่ได้ เพราะ
// prefix อยู่ที่ ifa-destination ไม่ได้ติดมากับ ifa-local) - Cisco ยังต้องมี
// subnet จริง ๆ เพราะต้องเอา prefix ไปคำนวณ network address
export function selectAnyRoutingNetworks({ interfaceRows = [], isJuniper = false } = {}) {
  const selected = [];
  const seen = new Set();
  for (const row of interfaceRows) {
    const ip = normalizeIP(row?.ip);
    if (!ip || ip === "-" || !isPrivateIPv4(ip)) continue;
    let value = null;
    if (isJuniper) {
      value = isJuniperRoutableUnit(row?.name) ? row.name : null;
    } else {
      const subnet = normalizeSubnet(row?.subnet);
      value = subnet ? networkAddressOf(ip, subnet.prefix) : null;
    }
    if (!value || seen.has(value)) continue;
    seen.add(value);
    selected.push(value);
  }
  return selected;
}
