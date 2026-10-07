function ensureArray(value) {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

// Junos มัก round-trip host address เป็น /32 ขณะที่บางค่าใน NAT parser อาจไม่มี
// prefix จึงต้องเทียบแบบ canonical ไม่เช่นนั้น Edit หา interface เดิมไม่เจอและ
// cleanup เข้าใจผิดว่า address คนละตัว
export function normalizeProxyArpAddress(value) {
  const text = String(value ?? "").trim();
  if (!text) return "";
  const sections = text.split("/");
  if (sections.length > 2) return text;
  const octets = sections[0].split(".");
  if (octets.length !== 4 || octets.some((part) => !/^\d{1,3}$/.test(part) || Number(part) > 255)) {
    return text;
  }
  const prefix = sections.length === 1 ? 32 : Number(sections[1]);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return text;
  const values = octets.map(Number);
  const number = values.reduce((result, octet) => ((result << 8) | octet) >>> 0, 0);
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const network = (number & mask) >>> 0;
  const address = [24, 16, 8, 0].map((shift) => (network >>> shift) & 0xff).join(".");
  return `${address}/${prefix}`;
}

export function proxyArpAddressesEqual(left, right) {
  const normalizedLeft = normalizeProxyArpAddress(left);
  return !!normalizedLeft && normalizedLeft === normalizeProxyArpAddress(right);
}

function ipv4Range(value) {
  const text = String(value ?? "").trim();
  const sections = text.split("/");
  if (!text || sections.length > 2) return null;
  const octets = sections[0].split(".");
  if (octets.length !== 4 || octets.some((part) => !/^\d{1,3}$/.test(part) || Number(part) > 255)) {
    return null;
  }
  const prefix = sections.length === 1 ? 32 : Number(sections[1]);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return null;
  const address = octets.reduce((result, octet) => result * 256 + Number(octet), 0);
  const size = 2 ** (32 - prefix);
  const first = Math.floor(address / size) * size;
  return {first, last: first + size - 1, prefix};
}

// Junos forbids Proxy ARP when its range overlaps an IP configured directly
// on any local interface.  For an exact host address (/32), Proxy ARP is also
// unnecessary because the device already owns and answers ARP for that IP.
// A wider range that contains a local address cannot simply omit Proxy ARP:
// the remaining addresses would stop answering, so report it as an overlap
// and let the form reject it explicitly.
export function classifyProxyArpForWanAddress(interfaceRows, address) {
  const target = ipv4Range(address);
  if (!target) return "required"; // input validation reports malformed values
  const overlaps = ensureArray(interfaceRows).some((row) =>
    ensureArray(row?.ip).some((configured) => {
      const host = ipv4Range(String(configured ?? "").split("/")[0]);
      return host && host.first >= target.first && host.first <= target.last;
    }),
  );
  if (!overlaps) return "required";
  return target.prefix === 32 ? "not-required" : "overlap";
}

export function proxyArpBindings(result) {
  const interfaces = ensureArray(
    result?.payload?.data?.configuration?.security?.nat?.["proxy-arp"]?.interface,
  );
  const bindings = [];
  for (const iface of interfaces) {
    if (!iface?.name) continue;
    for (const address of ensureArray(iface.address)) {
      const name = typeof address === "string" ? address : address?.name;
      if (name) bindings.push({interfaceName: iface.name, address: name});
    }
  }
  return bindings;
}

export function proxyArpInterfaceForAddress(result, address) {
  return proxyArpBindings(result).find((binding) =>
    proxyArpAddressesEqual(binding.address, address),
  )?.interfaceName || "";
}
