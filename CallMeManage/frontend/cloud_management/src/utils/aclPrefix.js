import { validateIPv4Input } from "./ipv4Input.js";

/**
 * Converts a prefix integer (0–32) to a dotted wildcard mask.
 * Example: 24 -> "0.0.0.255", 0 -> "255.255.255.255", 32 -> "0.0.0.0"
 * @param {number} prefix
 * @returns {string}
 */
export function prefixToWildcard(prefix) {
  if (typeof prefix !== "number" || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
    throw new Error("Prefix must be an integer between 0 and 32");
  }
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const wildcard = (~mask) >>> 0;
  return [24, 16, 8, 0].map((shift) => (wildcard >>> shift) & 0xff).join(".");
}

/**
 * Converts a contiguous wildcard mask to a prefix integer.
 * Rejects non-contiguous wildcards (returns { representable: false, prefix: null }).
 * @param {string} wildcard
 * @returns {{ representable: boolean, prefix: number | null, error?: string }}
 */
export function wildcardToPrefix(wildcard) {
  if (typeof wildcard !== "string") {
    return { representable: false, prefix: null, error: "Wildcard must be a string" };
  }
  const text = wildcard.trim();
  const octets = text.split(".");
  if (
    octets.length !== 4 ||
    octets.some((part) => !/^(0|[1-9][0-9]{0,2})$/.test(part) || Number(part) > 255)
  ) {
    return { representable: false, prefix: null, error: "Invalid wildcard format" };
  }
  const wildcardInt = octets.reduce((acc, octet) => ((acc << 8) | Number(octet)) >>> 0, 0);
  const maskInt = (~wildcardInt) >>> 0;

  // Verify contiguous 1 bits followed by 0 bits
  let prefix = 0;
  let seenZero = false;
  for (let bit = 31; bit >= 0; bit--) {
    const isOne = ((maskInt >>> bit) & 1) === 1;
    if (isOne) {
      if (seenZero) return { representable: false, prefix: null };
      prefix++;
    } else {
      seenZero = true;
    }
  }
  return { representable: true, prefix };
}

/**
 * Converts address and optional wildcard read from device into display string and metadata.
 * @param {string} address
 * @param {string|null} wildcard
 * @returns {{
 *   display: string,
 *   address: string,
 *   wildcard: string|null,
 *   cidr: string|null,
 *   prefix: number|null,
 *   representable: boolean,
 *   mode: "any" | "specific" | "none"
 * }}
 */
export function aclAddressToCidr(address, wildcard) {
  if (!address || address === "-") {
    return {
      display: "-",
      address: "",
      wildcard: null,
      cidr: "",
      prefix: null,
      representable: true,
      mode: "none",
    };
  }
  const addr = String(address).trim();
  if (addr === "any") {
    return {
      display: "any",
      address: "any",
      wildcard: null,
      cidr: "any",
      prefix: null,
      representable: true,
      mode: "any",
    };
  }

  // Host form (no wildcard or 0.0.0.0)
  if (!wildcard || wildcard.trim() === "" || wildcard === "0.0.0.0") {
    return {
      display: `${addr}/32`,
      address: addr,
      wildcard: null,
      cidr: `${addr}/32`,
      prefix: 32,
      representable: true,
      mode: "specific",
    };
  }

  const wp = wildcardToPrefix(wildcard);
  if (wp.representable) {
    return {
      display: `${addr}/${wp.prefix}`,
      address: addr,
      wildcard: wildcard.trim(),
      cidr: `${addr}/${wp.prefix}`,
      prefix: wp.prefix,
      representable: true,
      mode: "specific",
    };
  }

  // Non-contiguous wildcard (unrepresentable as CIDR)
  return {
    display: `${addr} wildcard ${wildcard.trim()}`,
    address: addr,
    wildcard: wildcard.trim(),
    cidr: null,
    prefix: null,
    representable: false,
    mode: "specific",
  };
}

/**
 * Validates and splits a CIDR string into address and prefix.
 * @param {string} value
 * @returns {{ valid: boolean, address?: string, prefix?: number, value?: string, error?: string }}
 */
export function splitValidatedCidr(value) {
  const check = validateIPv4Input(value, { mode: "cidr", required: true });
  if (!check.valid) {
    return { valid: false, error: check.error || "Please enter a valid IPv4/Prefix" };
  }
  return {
    valid: true,
    address: check.address,
    prefix: check.prefix,
    value: check.value,
  };
}
