import { validateIPv4Input } from "./ipv4Input.js";

const PREFIX_PATTERN = /^(0|[1-9][0-9]{0,2})$/;

function fail(error, empty = false) {
  return { valid: false, complete: false, empty, error, value: null };
}

function parseIPv6Address(address) {
  if (!address || address.includes("%")) return null;

  let normalized = address;
  if (normalized.includes(".")) {
    const lastColon = normalized.lastIndexOf(":");
    if (lastColon < 0) return null;
    const ipv4 = validateIPv4Input(normalized.slice(lastColon + 1), { mode: "address" });
    if (!ipv4.valid) return null;
    const octets = ipv4.value.split(".").map(Number);
    const high = ((octets[0] << 8) | octets[1]).toString(16);
    const low = ((octets[2] << 8) | octets[3]).toString(16);
    normalized = `${normalized.slice(0, lastColon)}:${high}:${low}`;
  }

  const compressed = normalized.indexOf("::");
  if (compressed !== normalized.lastIndexOf("::")) return null;

  const hasCompression = compressed >= 0;
  const [leftText, rightText = ""] = hasCompression
    ? [normalized.slice(0, compressed), normalized.slice(compressed + 2)]
    : [normalized, ""];
  const left = leftText ? leftText.split(":") : [];
  const right = rightText ? rightText.split(":") : [];
  const groups = [...left, ...right];

  if (groups.some((group) => !/^[0-9a-fA-F]{1,4}$/.test(group))) return null;
  if ((!hasCompression && groups.length !== 8) || (hasCompression && groups.length >= 8)) return null;

  const zeros = hasCompression ? Array(8 - groups.length).fill("0") : [];
  const expanded = [...left, ...zeros, ...right].map((group) => Number.parseInt(group, 16));
  if (expanded.length !== 8) return null;
  return expanded.reduce((result, group) => (result << 16n) | BigInt(group), 0n);
}

function formatIPv6(number) {
  const groups = Array.from({ length: 8 }, (_, index) =>
    Number((number >> BigInt((7 - index) * 16)) & 0xffffn).toString(16));

  let bestStart = -1;
  let bestLength = 0;
  for (let index = 0; index < groups.length;) {
    if (groups[index] !== "0") {
      index += 1;
      continue;
    }
    let end = index;
    while (end < groups.length && groups[end] === "0") end += 1;
    if (end - index > bestLength) {
      bestStart = index;
      bestLength = end - index;
    }
    index = end;
  }

  if (bestLength < 2) return groups.join(":");
  const left = groups.slice(0, bestStart).join(":");
  const right = groups.slice(bestStart + bestLength).join(":");
  return `${left}::${right}`;
}

function normalizeIPv4Network(address, prefix) {
  const octets = address.split(".").map(Number);
  const number = octets.reduce((result, octet) => ((result << 8) | octet) >>> 0, 0);
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const network = (number & mask) >>> 0;
  return [24, 16, 8, 0].map((shift) => (network >>> shift) & 255).join(".");
}

/**
 * Validate and normalize an IPv4 or IPv6 prefix for YANG `inet:ip-prefix`.
 * A bare address is accepted and becomes /32 (IPv4) or /128 (IPv6).
 */
export function validateIPPrefixInput(value, { required = true } = {}) {
  if (typeof value !== "string") return fail("Value must be an IP address/prefix string");
  const text = value.trim();
  if (!text) {
    return required
      ? fail("Please enter IP address/prefix", true)
      : { valid: true, complete: false, empty: true, error: "", value: "" };
  }

  const sections = text.split("/");
  if (sections.length > 2 || !sections[0]) return fail("Use IP address or IP address/prefix format");

  const address = sections[0];
  const isIPv6 = address.includes(":");
  const maxPrefix = isIPv6 ? 128 : 32;
  const rawPrefix = sections.length === 2 ? sections[1] : String(maxPrefix);
  if (!PREFIX_PATTERN.test(rawPrefix) || Number(rawPrefix) > maxPrefix) {
    return fail(`Prefix must be an integer between 0 and ${maxPrefix}`);
  }
  const prefix = Number(rawPrefix);

  if (!isIPv6) {
    const parsed = validateIPv4Input(address, { mode: "address" });
    if (!parsed.valid) return fail(parsed.error);
    const network = normalizeIPv4Network(parsed.value, prefix);
    return {
      valid: true, complete: true, empty: false, error: "", family: 4,
      address: network, prefix, value: `${network}/${prefix}`,
    };
  }

  const parsed = parseIPv6Address(address);
  if (parsed === null) return fail("Invalid IPv6 address");
  const hostBits = BigInt(128 - prefix);
  const network = hostBits === 0n ? parsed : (parsed >> hostBits) << hostBits;
  const normalized = formatIPv6(network);
  return {
    valid: true, complete: true, empty: false, error: "", family: 6,
    address: normalized, prefix, value: `${normalized}/${prefix}`,
  };
}
