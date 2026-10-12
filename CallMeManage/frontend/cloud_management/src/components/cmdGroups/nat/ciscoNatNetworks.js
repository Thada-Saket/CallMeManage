function ensureArray(value) {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

function ipv4ToInt(value) {
  const parts = String(value ?? "").trim().split(".").map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return null;
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

function intToIpv4(value) {
  return [24, 16, 8, 0].map((shift) => (value >>> shift) & 255).join(".");
}

function isPrivateNetwork(cidr) {
  const ip = ipv4ToInt(String(cidr).split("/")[0]);
  return ip !== null && (
    (ip >= ipv4ToInt("10.0.0.0") && ip <= ipv4ToInt("10.255.255.255")) ||
    (ip >= ipv4ToInt("172.16.0.0") && ip <= ipv4ToInt("172.31.255.255")) ||
    (ip >= ipv4ToInt("192.168.0.0") && ip <= ipv4ToInt("192.168.255.255"))
  );
}

function maskToPrefix(mask) {
  const number = ipv4ToInt(mask);
  if (number === null) return null;
  const bits = number.toString(2).padStart(32, "0");
  if (!/^1*0*$/.test(bits)) return null;
  const firstZero = bits.indexOf("0");
  return firstZero < 0 ? 32 : firstZero;
}

export function normalizeCidr(value) {
  const [address, prefixText, extra] = String(value ?? "").trim().split("/");
  const ip = ipv4ToInt(address);
  const prefix = Number(prefixText);
  if (extra !== undefined || ip === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) return null;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return `${intToIpv4(ip & mask)}/${prefix}`;
}

export function isNetworkCidr(value) {
  const text = String(value ?? "").trim();
  const normalized = normalizeCidr(text);
  return normalized !== null && normalized === text;
}

export function connectedNatNetworks(ifaceRows, selectedNames) {
  const selected = new Set(selectedNames || []);
  const networks = [];
  for (const row of ifaceRows || []) {
    if (!selected.has(row?.name)) continue;
    const ip = ipv4ToInt(row?.ip);
    const prefix = maskToPrefix(row?.subnet);
    if (ip === null || prefix === null) continue;
    const cidr = normalizeCidr(`${row.ip}/${prefix}`);
    if (cidr) networks.push({ cidr, via: row.name });
  }
  return [...new Map(networks.map((item) => [item.cidr, item])).values()];
}

export function ciscoRouteNetworkSuggestions(result, outsideInterface = "") {
  const routingState = result?.payload?.data?.["routing-state"];
  const suggestions = [];
  for (const instance of ensureArray(routingState?.["routing-instance"])) {
    for (const rib of ensureArray(instance?.ribs?.rib)) {
      for (const route of ensureArray(rib?.routes?.route)) {
        const cidr = normalizeCidr(route?.["destination-prefix"]);
        // Discovery is intentionally conservative: an Internet/BGP table can
        // contain thousands of public routes. Unusual LAN ranges remain easy
        // to add through the CIDR input without flooding a beginner's form.
        if (!cidr || !isNetworkCidr(route?.["destination-prefix"]) || cidr === "0.0.0.0/0" || !isPrivateNetwork(cidr)) continue;
        const nextHop = route?.["next-hop"] || {};
        const iface = nextHop?.["outgoing-interface"] || "";
        if (outsideInterface && iface === outsideInterface) continue;
        suggestions.push({
          cidr,
          via: iface,
          protocol: String(route?.["source-protocol"] || "").replace(/^.*:/, ""),
        });
      }
    }
  }
  return [...new Map(suggestions.map((item) => [item.cidr, item])).values()];
}

export function uniqueNatScopes(...groups) {
  const scopes = [];
  for (const value of groups.flat()) {
    const cidr = normalizeCidr(value);
    if (cidr && cidr !== "0.0.0.0/0" && !scopes.includes(cidr)) scopes.push(cidr);
  }
  return scopes;
}
