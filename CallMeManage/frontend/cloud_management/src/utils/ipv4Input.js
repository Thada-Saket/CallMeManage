/** Explicit IPv4 input modes. No inference between netmask and wildcard. */
export const IPV4_MODES = ["address", "cidr", "subnet", "wildcard"];

const digits = /^(0|[1-9][0-9]{0,2})$/;
const toInt = octets => octets.reduce((number, octet) => ((number << 8) | Number(octet)) >>> 0, 0);

export function splitIPv4Draft(value = "", mode = "address") {
  const text = typeof value === "string" ? value : "";
  const [address = "", prefix = ""] = text.split("/");
  const octets = address.split(".");
  return {octets: Array.from({length: 4}, (_, index) => octets[index] || ""), prefix: mode === "cidr" ? prefix : ""};
}

export function joinIPv4Draft({octets, prefix = ""}, mode = "address") {
  if (octets.every(value => value === "") && !prefix) return "";
  return octets.join(".") + (mode === "cidr" ? "/" + prefix : "");
}

export function validateIPv4Input(value, {mode = "address", required = true,
  networkOnly = false, hostOnly = false, contiguousWildcard = false} = {}) {
  if (!IPV4_MODES.includes(mode)) throw new Error("Unknown IPv4 input mode: " + mode);
  const fail = (error, complete = false, empty = false) => ({valid: false, complete, empty, error, value: null});
  if (typeof value !== "string") return fail("Value must be an IPv4 string");
  const text = value.trim();
  if (!text) return required ? fail("Please fill in all fields", false, true)
    : {valid: true, complete: false, empty: true, error: "", value: ""};
  const sections = text.split("/");
  if (sections.length !== (mode === "cidr" ? 2 : 1)) return fail(mode === "cidr" ? "Use address/prefix format" : "Use four IPv4 octets only");
  const octets = sections[0].split(".");
  if (octets.length !== 4 || octets.some(part => part === "")) return fail("Please fill in all four IPv4 octets");
  if (octets.some(part => !digits.test(part) || Number(part) > 255)) return fail("Each octet must be 0–255 with no leading zeros", true);
  const address = octets.join(".");
  const number = toInt(octets);
  let prefix;
  if (mode === "cidr") {
    if (!sections[1]) return fail("Please enter prefix");
    if (!/^(0|[1-9][0-9]?)$/.test(sections[1]) || Number(sections[1]) > 32) return fail("Prefix must be an integer between 0 and 32", true);
    prefix = Number(sections[1]);
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    const network = (number & mask) >>> 0;
    const broadcast = (network | (~mask >>> 0)) >>> 0;
    if (networkOnly && number !== network) return fail("Must be a network address", true);
    if (hostOnly && prefix < 31 && (number === network || number === broadcast)) return fail("Must be a host address, not network/broadcast", true);
  }
  if (mode === "subnet") {
    const inverse = (~number) >>> 0;
    if ((inverse & (inverse + 1)) !== 0) return fail("Subnet mask must have contiguous 1 bits followed by 0 bits", true);
  }
  if (mode === "wildcard" && contiguousWildcard && (number & (number + 1)) !== 0) return fail("Contiguous wildcard is required", true);
  return {valid: true, complete: true, empty: false, error: "", address, prefix,
    value: mode === "cidr" ? address + "/" + prefix : address};
}

/** Return a validated full paste, or null. Never strip arbitrary pasted characters. */
export function parseIPv4Paste(text, mode = "address") {
  if (typeof text !== "string") return null;
  const value = text.trim();
  const parsed = validateIPv4Input(value, {mode});
  if (parsed.valid) return splitIPv4Draft(parsed.value, mode);
  if (mode === "cidr" && !value.includes("/") && validateIPv4Input(value).valid) return splitIPv4Draft(value, mode);
  return null;
}

export function acceptsIPv4Segment(value, prefix = false) {
  return typeof value === "string" && /^[0-9]*$/.test(value)
    && !(value.length > 1 && value[0] === "0")
    && value.length <= (prefix ? 2 : 3) && (value === "" || Number(value) <= (prefix ? 32 : 255));
}
