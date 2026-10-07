function ipToInt(ip) {
  if (typeof ip !== "string" || !/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return null;
  const octets = ip.split(".").map(Number);
  if (octets.some((octet) => octet > 255)) return null;
  return ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;
}

function intToIp(value) {
  return [24, 16, 8, 0].map((shift) => (value >>> shift) & 255).join(".");
}

// Reservation includes the gateway, leaving at least one client address.
export function computeAdaptiveDhcpRange(ip, prefix) {
  const ipInt = ipToInt(ip);
  if (ipInt === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 30) return null;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const network = (ipInt & mask) >>> 0;
  const usableHosts = 2 ** (32 - prefix) - 2;
  const reservedCount = prefix >= 30 ? 1 : prefix >= 28 ? 2 : prefix >= 26 ? 4 : prefix >= 24 ? 10 : 20;
  const reserved = Math.min(reservedCount, usableHosts - 1);
  return {
    start: intToIp(network + 1 + reserved),
    end: intToIp(network + usableHosts),
    gateway: intToIp(network + 1),
  };
}

export function computeDhcpDefaults(networkCidr) {
  if (typeof networkCidr !== "string") return null;
  const match = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/.exec(networkCidr.trim());
  return match ? computeAdaptiveDhcpRange(match[1], Number(match[2])) : null;
}
