// |====== Normalize subnet/wildcard to prefix ======|

// ผู้ใช้กรอกขนาด subnet มาได้ 3 แบบ: prefix length ("24"), subnet mask
// ("255.255.255.0"), หรือ wildcard mask ("0.0.0.255" - ใช้กับ OSPF network
// ของ Cisco) - ฟังก์ชันนี้เดาว่า input เป็นแบบไหนจาก "รูปร่าง" ของค่าเอง แล้ว
// แปลงเป็นทั้ง 3 แบบให้พร้อมกันครั้งเดียว ไม่ต้องให้ผู้ใช้บอกว่ากรอกแบบไหนมา -
// ฝั่งเรียกใช้ (แต่ละ FormModal) แค่เลือกหยิบ field ที่ตรงกับ backend command
// ของตัวเอง: set_interface_static_ip/set_sub_interface_ip/set_interface_vlan/
// set_static_route ต้องการ prefix (int), set_ospf_network ต้องการ wildcardMask
// (str) - ยังไม่มี command ไหนต้องการ subnetMask ตรงๆ ตอนนี้ (backend มี
// prefix_translator() แปลง prefix->subnet mask ให้เองอยู่แล้ว) แต่เก็บไว้ให้
// ครบเผื่ออนาคต

function ipToInt(ip) {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  if (parts.some(part => !/^(0|[1-9][0-9]{0,2})$/.test(part))) return null;
  const octets = parts.map(Number);
  if (octets.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;
}

function intToIp(value) {
  return [24, 16, 8, 0].map((shift) => (value >>> shift) & 0xff).join(".");
}

function prefixFromLeftAlignedMask(maskInt) {
  let prefix = 0;
  let seenZero = false;
  for (let bit = 31; bit >= 0; bit--) {
    const isOne = ((maskInt >>> bit) & 1) === 1;
    if (isOne) {
      if (seenZero) return null; // มีบิต 1 โผล่มาหลังบิต 0 แล้ว -> ไม่ใช่ mask ที่ถูกต้อง
      prefix++;
    } else {
      seenZero = true;
    }
  }
  return prefix;
}

function prefixToMaskInt(prefix) {
  return prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
}

// แปลง subnet หรือ wildcard ให้กลายเป็น prefix เช่นจาก 255.255.255.0 ให้กลายเป็น 24
export function normalizeSubnet(input) {
  if (input === null || input === undefined || input === "") return null;
  const raw = String(input).trim();

  // แบบที่ 1: prefix length ตรงๆ (ตัวเลขล้วน 0-32 ไม่มีจุด)
  if (/^\d{1,2}$/.test(raw)) {
    const prefix = Number(raw);
    if (prefix < 0 || prefix > 32) return null;
    const maskInt = prefixToMaskInt(prefix);
    return {
      prefix,
      subnetMask: intToIp(maskInt),
      wildcardMask: intToIp(~maskInt >>> 0),
    };
  }

  const maskInt = ipToInt(raw);
  if (maskInt === null) return null;

  let prefix = prefixFromLeftAlignedMask(maskInt);
  if (prefix !== null) {
    return {
      prefix,
      subnetMask: intToIp(maskInt),
      wildcardMask: intToIp(~maskInt >>> 0),
    };
  }

  const complementInt = ~maskInt >>> 0;
  prefix = prefixFromLeftAlignedMask(complementInt);
  if (prefix !== null) {
    return {
      prefix,
      subnetMask: intToIp(complementInt),
      wildcardMask: intToIp(maskInt),
    };
  }

  return null; // ไม่ใช่ทั้ง prefix, subnet mask, wildcard mask ที่ถูกต้อง
}
