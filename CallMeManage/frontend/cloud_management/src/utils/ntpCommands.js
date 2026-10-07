function ensureArray(value) {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

export function uniqueStrings(values) {
  return [...new Set(values.map((value) => String(value || "").trim()).filter(Boolean))];
}

// Huawei ระบุ ntpUCastCfg ด้วย composite key 6 ค่า ไม่ใช่ IPv4 เพียงค่าเดียว
// เก็บ key จาก reply เดิมไว้ครบเพื่อให้คำสั่ง remove ชี้ไปยัง instance จริงบนอุปกรณ์
export function parseHuaweiNtpEntries(result) {
  const entries = result?.payload?.data?.ntp?.ntpUCastCfgs?.ntpUCastCfg;
  const seen = new Set();

  return ensureArray(entries)
    .filter((entry) => {
      const family = String(entry?.addrFamily || "").toLowerCase();
      const type = String(entry?.type || "").toLowerCase();
      return family === "ipv4" && type === "server" && entry?.ipv4Addr;
    })
    .map((entry) => ({
      addrFamily: String(entry.addrFamily),
      ipv4Addr: String(entry.ipv4Addr).trim(),
      ipv6Addr: String(entry.ipv6Addr ?? "::"),
      type: String(entry.type),
      vpnName: String(entry.vpnName ?? "_public_"),
      neid: String(entry.neid ?? "0-0"),
    }))
    .filter((entry) => {
      const key = [
        entry.addrFamily,
        entry.ipv4Addr,
        entry.ipv6Addr,
        entry.type,
        entry.vpnName,
        entry.neid,
      ].join("\u0000");
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
}

// get_ntp_information ใช้ generic normalizer จึงต้องอ่าน path ของแต่ละ vendor
// โดยตรง และรองรับทั้งกรณี XML มีรายการเดียว (object) กับหลายรายการ (array)
export function parseNtpResult(result) {
  const vendor = result?.vendor;

  if (vendor === "cisco") {
    const entries = result?.payload?.data?.native?.ntp?.server?.["server-list"];
    return uniqueStrings(
      ensureArray(entries).map((entry) =>
        typeof entry === "string" ? entry : entry?.["ip-address"],
      ),
    );
  }

  if (vendor === "juniper") {
    const entries = result?.payload?.data?.configuration?.system?.ntp?.server;
    return uniqueStrings(
      ensureArray(entries).map((entry) => (typeof entry === "string" ? entry : entry?.name)),
    );
  }

  if (vendor === "huawei") {
    return uniqueStrings(parseHuaweiNtpEntries(result).map((entry) => entry.ipv4Addr));
  }

  return [];
}

// คำนวณเฉพาะรายการที่เปลี่ยน (remove ก่อน set) ผลลัพธ์ว่าง = ไม่มีอะไรต้องส่ง
export function buildNtpCommands(vendor, result, requestedServers) {
  const currentServers = parseNtpResult(result);
  const removed = currentServers.filter((server) => !requestedServers.includes(server));
  const added = requestedServers.filter((server) => !currentServers.includes(server));
  const removeCommands = vendor === "huawei"
    ? parseHuaweiNtpEntries(result)
        .filter((entry) => !requestedServers.includes(entry.ipv4Addr))
        .map((entry) => ({
          command: "remove_ntp_server",
          parameters: {
            ntp_ip: entry.ipv4Addr,
            addr_family: entry.addrFamily,
            ipv6_addr: entry.ipv6Addr,
            ntp_type: entry.type,
            vpn_name: entry.vpnName,
            neid: entry.neid,
          },
        }))
    : removed.map((ntpIp) => ({
        command: "remove_ntp_server",
        parameters: { ntp_ip: ntpIp },
      }));
  return [
    ...removeCommands,
    ...added.map((ntpIp) => ({ command: "set_ntp_server", parameters: { ntp_ip: ntpIp } })),
  ];
}

// ทุก vendor ส่งเป็น transaction เดียว (backend ตรวจ+build payload ครบก่อนแตะอุปกรณ์)
// ไม่มีการ validate/รันทีละคำสั่ง จึงไม่มี partial config และนับ rate limit ครั้งเดียว
// คืน true ถ้าส่ง mutation จริง
export async function applyNtpChanges({ devId, vendor, result, requestedServers, runTransaction }) {
  const commands = buildNtpCommands(vendor, result, requestedServers);
  if (commands.length === 0) return false;
  await runTransaction(devId, commands);
  return true;
}
