const ROUTING_STATUS_PROTOCOLS = [
  { pattern: /(?:^|[-_])ospf(?:v?\d+)?(?:$|[-_])/, label: "OSPF" },
  { pattern: /(?:^|[-_])rip(?:v?\d+)?(?:$|[-_])/, label: "RIP" },
  { pattern: /(?:^|[-_])static(?:$|[-_])/, label: "Static" },
  { pattern: /(?:^|[-_])(?:direct|connected|local)(?:$|[-_])/, label: "Direct" },
];

// Routing protocol identities differ between vendors and YANG models. Keep the
// dashboard vocabulary deliberately small instead of exposing those raw names.
export function normalizeRoutingStatusProtocol(value) {
  const normalized = String(value ?? "")
    .trim()
    .toLowerCase()
    .replace(/:/g, "-")
    .replace(/\s+/g, "-");
  if (!normalized) return null;

  return ROUTING_STATUS_PROTOCOLS.find(({ pattern }) => pattern.test(normalized))?.label || null;
}

function parseIPv4Cidr(value) {
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/.exec(value);
  if (!match) return null;

  const octets = match.slice(1, 5).map(Number);
  const prefixLength = Number(match[5]);
  if (octets.some((octet) => octet < 0 || octet > 255) || prefixLength < 0 || prefixLength > 32) {
    return null;
  }

  const address = octets.reduce((total, octet) => total * 256 + octet, 0);
  return { address, prefixLength };
}

// A prefix such as 192.168.1.1/24 represents an interface/local address rather
// than the routed network 192.168.1.0/24, so it is dashboard noise. Host routes
// (/32) are also intentionally omitted from this compact status view.
export function isCanonicalIPv4NetworkPrefix(value) {
  const parsed = parseIPv4Cidr(String(value ?? "").trim());
  if (!parsed) return false;
  if (parsed.prefixLength === 32) return false;
  const blockSize = 2 ** (32 - parsed.prefixLength);
  return parsed.address % blockSize === 0;
}

export function routingStatusRoutes(routes, vendor) {
  if (!Array.isArray(routes)) return routes;
  const normalizedVendor = String(vendor || "").toLowerCase();

  return routes.flatMap((route) => {
    const prefix = String(route?.prefix ?? "").trim();
    const protocol = normalizeRoutingStatusProtocol(route?.protocol);
    if (!prefix || !protocol) return [];

    if (normalizedVendor === "juniper") {
      if (prefix.includes(":")) return [];
      if (prefix.toLowerCase() === "224.0.0.5/32") return [];
    }

    // Apply the network-address check to IPv4 CIDRs. Non-Juniper IPv6 is left
    // unchanged because the product requirement only removes IPv6 from Junos.
    if (!prefix.includes(":") && !isCanonicalIPv4NetworkPrefix(prefix)) return [];

    return [{ ...route, prefix, protocol }];
  });
}
