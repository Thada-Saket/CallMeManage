export function ciscoNatOutboundInterfaces(switchportRows, outsideName = null) {
  const names = (switchportRows || [])
    .filter((row) => row?.layer === "Layer 3" && row?.name)
    .map((row) => row.name);

  // `ip nat outside` เป็นหลักฐานจาก running config ว่าขานี้ทำงานเป็น routed
  // interface อยู่จริง เก็บไว้ในตัวเลือกแม้ข้อมูล layer จากอีก YANG model จะขาด
  // เพื่อไม่ให้ Edit แสดงค่าเดิมเป็นช่องว่าง
  if (outsideName) names.push(outsideName);
  return [...new Set(names)];
}

export function initialCiscoNatOutbound(currentRule, outsideName) {
  if (outsideName) return outsideName;
  return currentRule?.mode === "interface" ? currentRule.target || "" : "";
}

function ipv4ToInt(value) {
  const parts = String(value ?? "").trim().split(".");
  if (parts.length !== 4) return null;
  const octets = parts.map(Number);
  if (octets.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return null;
  return ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;
}

export function isPrivateIPv4(value) {
  const ip = ipv4ToInt(value);
  if (ip === null) return false;
  return (
    (ip >= ipv4ToInt("10.0.0.0") && ip <= ipv4ToInt("10.255.255.255")) ||
    (ip >= ipv4ToInt("172.16.0.0") && ip <= ipv4ToInt("172.31.255.255")) ||
    (ip >= ipv4ToInt("192.168.0.0") && ip <= ipv4ToInt("192.168.255.255"))
  );
}

function hasUsableIPv4(value) {
  const ip = ipv4ToInt(value);
  // IOS-XE may report 0.0.0.0 for an interface without an assigned address.
  return ip !== null && ip !== 0;
}

// NAT inside is an interface role on IOS-XE; it is not restricted to RFC1918.
// Offer every interface with a configured IPv4 address, but also retain an
// interface that is already `ip nat inside` when operational IP telemetry is
// missing. The latter prevents a brownfield Apply from silently removing it.
export function ciscoNatInsideCandidates(ifaceRows, via, configuredInsideNames = []) {
  const configured = new Set((configuredInsideNames || []).filter(Boolean));
  const rowsByName = new Map(
    (ifaceRows || []).filter((row) => row?.name).map((row) => [row.name, row])
  );
  const candidates = [];
  const seen = new Set();

  for (const row of ifaceRows || []) {
    if (!row?.name || row.name === via || !hasUsableIPv4(row.ip) || seen.has(row.name)) continue;
    candidates.push({ ...row, configuredNatInside: configured.has(row.name) });
    seen.add(row.name);
  }

  for (const name of configured) {
    if (name === via || seen.has(name)) continue;
    candidates.push({
      ...(rowsByName.get(name) || {}),
      name,
      configuredNatInside: true,
      ipUnavailable: true,
    });
    seen.add(name);
  }

  return candidates;
}

// Keep the existing create behavior: RFC1918 interfaces are selected by
// default. Public/special-use IPv4 interfaces are available but opt-in only.
export function defaultCiscoNatInsideNames(ifaceRows, via) {
  return ciscoNatInsideCandidates(ifaceRows, via)
    .filter((row) => isPrivateIPv4(row.ip))
    .map((row) => row.name);
}
