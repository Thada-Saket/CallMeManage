// แยกออกมาจาก security_tunnel.jsx (เดิมเป็น function ในไฟล์นั้น) เพราะหน้า
// security_profile.jsx ต้องใช้ตรรกะเดียวกันด้วย - ต้องรู้ว่า profile ที่กำลังจะลบ/
// เปลี่ยนชื่อมี tunnel ตัวไหนผูกอยู่หรือเปล่า (bug 67) ถ้า copy ไปอีกไฟล์แล้ววันหนึ่ง
// โครงสร้าง XML ของอุปกรณ์เปลี่ยน จะต้องไล่แก้ 2 ที่และพลาดง่าย
function ensureArray(value) {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

// Junos: security/ipsec/vpn (bind-interface + ike/gateway+ipsec-policy) join
// กับ security/ike/gateway (external-interface/address ที่ create_security_tunnel
// merge เข้าไปทีหลัง) join กับ interfaces/interface[name=st0]/unit (family/inet/
// address ที่เป็น tunnel IP จริง) - 3 ส่วนนี้มาจากคำสั่งเดียวกัน + gr-* interface
// (GRE - unit/tunnel/source+destination ตรงๆ ไม่ผ่าน security object เลย) รวม
// เป็นตารางเดียวกัน - get_security_tunnel_information ขอทั้ง interfaces subtree
// มาเลย (ไม่รู้ล่วงหน้าว่ามี gr- กี่ตัว/ชื่ออะไร) เลยมี interface อื่นที่ไม่
// เกี่ยวปนมาด้วยเสมอ (ge-x, fxp0, irb ฯลฯ) ต้องกรองเอาเฉพาะ "st0"/"gr-*" เอง
function parseJuniperSecurityTunnels(result) {
  const configuration = result?.payload?.data?.configuration || {};
  const allInterfaces = ensureArray(configuration?.interfaces?.interface);

  const gatewayByName = {};
  for (const gw of ensureArray(configuration?.security?.ike?.gateway)) {
    if (gw?.name) gatewayByName[gw.name] = gw;
  }
  // ขอบเขตจำกัดเฉพาะ unit ของ "st0" เท่านั้น (ไม่ใช่ทุก interface ที่ query มา -
  // เดิมทำ map รวมทุก interface ไว้ในกุญแจเดียวกัน (unit number ดิบ) ตอนนี้ query
  // กว้างขึ้นแล้ว interface อื่น (เช่น gr-0/0/0 unit "0", ge-0/0/2 unit "0") จะมี
  // unit number ชนกันได้ ทำให้ join ผิดตัว - จำกัด scope ให้ตรงเฉพาะ st0 เท่านั้น)
  const st0UnitByNumber = {};
  // mtu ของ st0 อยู่ระดับ physical interface (sibling ของ unit) แชร์กันทุก
  // st0.X - เก็บแยกไว้ต่างหาก (ไม่ใช่ต่อ unit) ตรงกับที่ create_security_tunnel
  // เขียนจริง (ดู juniper_junos.py's create_security_tunnel comment)
  let st0Mtu = null;
  for (const entry of allInterfaces) {
    if (entry?.name !== "st0") continue;
    if (entry?.mtu !== undefined) st0Mtu = entry.mtu;
    for (const unit of ensureArray(entry?.unit)) {
      if (unit?.name !== undefined) st0UnitByNumber[String(unit.name)] = unit;
    }
  }

  const ipsecRows = ensureArray(configuration?.security?.ipsec?.vpn).map((vpn) => {
    const bindInterface = vpn?.["bind-interface"] || "";
    const unitNumber = bindInterface.includes(".") ? bindInterface.split(".").pop() : "";
    const st0Unit = st0UnitByNumber[unitNumber];
    const address = st0Unit?.family?.inet?.address?.name || "";
    const [tunIp, tunMask] = address.includes("/") ? address.split("/") : [address, ""];
    const gatewayName = vpn?.ike?.gateway || "";
    const gateway = gatewayByName[gatewayName] || {};
    const peerAddresses = ensureArray(gateway.address);
    const profileBase = gatewayName ? gatewayName.replace(/-GATEWAY$/, "") : null;
    const unitMtu = st0Unit?.family?.inet?.mtu;

    return {
      name: bindInterface || vpn?.name || "",
      type: "IPsec",
      tunIp,
      tunMask,
      source: gateway?.["external-interface"] || "",
      destination: peerAddresses[0] || "",
      securityProfile: profileBase,
      real: {
        vpnName: vpn?.name || "",
        bindInterface,
        unitNumber,
        gatewayName,
        ipsecPolicyName: vpn?.ike?.["ipsec-policy"] || "",
      },
      managed: /-GATEWAY$/.test(gatewayName) && vpn?.name === `${profileBase}-VPN`,
      mtu: unitMtu !== undefined ? unitMtu : st0Mtu,
    };
  });

  // GRE: gr-*/unit/tunnel/source+destination ตรงๆ (ไม่ผ่าน security object
  // เลย ต่างจาก IPsec) unit ที่ไม่มี tunnel container เลย (ไม่ใช่ GRE tunnel
  // ที่หน้านี้สร้าง) ข้ามไป - securityProfile เป็น null เสมอ (ไม่มี concept นี้
  // สำหรับ GRE)
  const greRows = [];
  for (const entry of allInterfaces) {
    if (!entry?.name?.startsWith("gr-")) continue;
    for (const unit of ensureArray(entry?.unit)) {
      const tunnel = unit?.tunnel;
      if (!tunnel) continue;
      const address = unit?.family?.inet?.address?.name || "";
      const [tunIp, tunMask] = address.includes("/") ? address.split("/") : [address, ""];
      const unitMtu = unit?.family?.inet?.mtu;
      greRows.push({
        name: `${entry.name}.${unit.name}`,
        type: "GRE",
        tunIp,
        tunMask,
        source: tunnel.source || "",
        destination: tunnel.destination || "",
        securityProfile: null,
        real: {
          interfaceName: entry.name,
          unitName: String(unit.name),
        },
        // create/remove_tunnel_interface ฝั่ง GRE ทำงานกับ **unit 0 เสมอ** (ตายตัวใน
        // translator ทั้งคู่) ส่วน frontend ส่งไปแค่ slot ที่ตัด `.N` ทิ้งแล้ว - GRE tunnel
        // ที่อยู่บน unit อื่น (ตั้งจาก CLI) จึงถูกสั่งลบ/แก้ผิด unit โดยไม่มีอะไรฟ้อง
        managed: String(unit.name) === "0",
        mtu: unitMtu !== undefined ? unitMtu : (entry?.mtu ?? null),
      });
    }
  }

  return [...ipsecRows, ...greRows];
}

// อ่านสดจาก get_security_tunnel_information (native/interface/Tunnel ทั้งหมด) -
// แยก IPsec vs GRE จาก key ที่มีอยู่ใน tunnel/mode (ตรงกับที่ create_security_tunnel
// เขียน: ipsec ใช้ mode/ipsec + มี protection, gre ใช้ mode/gre-config ไม่มี
// protection เลย)
export function parseSecurityTunnels(result) {
  if (result?.vendor === "juniper") {
    try {
      return parseJuniperSecurityTunnels(result);
    } catch {
      return null;
    }
  }
  try {
    const tunnels = ensureArray(result?.payload?.data?.native?.interface?.Tunnel);
    return tunnels.map((tunnel) => {
      const tunnelCfg = tunnel?.tunnel || {};
      const isIpsec = "ipsec" in (tunnelCfg.mode || {});
      const primary = tunnel?.ip?.address?.primary || {};
      return {
        name: `Tunnel${tunnel?.name ?? ""}`,
        type: isIpsec ? "IPsec" : "GRE",
        // Cisco แก้/ลบด้วย "เลข interface" ที่อ่านมาจากอุปกรณ์ตรง ๆ ไม่ได้ derive ชื่อ
        // object อื่นเลย จึงทำงานกับ Tunnel ที่ตั้งจาก CLI ได้เหมือนกัน (ต่างจาก Junos)
        managed: true,
        tunIp: primary.address || "",
        tunMask: primary.mask || "",
        source: tunnelCfg.source || "",
        destination: tunnelCfg["destination-config"]?.ipv4 || "",
        securityProfile: tunnelCfg?.protection?.ipsec?.["profile-option"]?.name || null,
        // ip mtu ของ Tunnel เก็บที่ tunnel.ip.mtu (sibling ของ tunnel.ip.address -
        // ดู cisco_iosxe.py's create_security_tunnel ที่แทรก <ip><mtu> เข้าไป
        // ในคำสั่งเดียวกับ tun_ip/tun_subnet)
        mtu: tunnel?.ip?.mtu ?? null,
      };
    });
  } catch {
    return null;
  }
}

// (bug 67) หา tunnel ทั้งหมดที่ผูกอยู่กับ security profile ชื่อนี้
//
// Cisco:   tunnel อ้าง profile ผ่าน "tunnel protection ipsec profile <name>-IPSEC-PROFILE"
//          parseSecurityTunnels คืนค่านั้นมาใน securityProfile ตรง ๆ จึงต้องตัด suffix ออก
//          ก่อนเทียบกับชื่อฐานที่ผู้ใช้เห็นในตาราง
// Juniper: ตัด "-GATEWAY" ออกไปแล้วตั้งแต่ตอน parse จึงเป็นชื่อฐานอยู่แล้ว
//
// คืนเป็น array ของ "ชื่อ tunnel" เพื่อเอาไปบอกผู้ใช้ได้เลยว่าตัวไหนใช้อยู่
export function findTunnelsUsingProfile(tunnels, profileName) {
  if (!Array.isArray(tunnels) || !profileName) return [];
  return tunnels
    .filter((tunnel) => {
      const bound = tunnel?.securityProfile;
      if (!bound) return false;
      const base = bound.replace(/-IPSEC-PROFILE$/, "").replace(/-GATEWAY$/, "");
      return base === profileName || bound === profileName;
    })
    .map((tunnel) => tunnel.name)
    .filter(Boolean);
}
