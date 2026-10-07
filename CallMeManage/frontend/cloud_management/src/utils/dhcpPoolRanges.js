const array = (value) => value == null ? [] : Array.isArray(value) ? value : [value];
function ipNumber(ip) {
  if (typeof ip !== "string" || !/^\d{1,3}(\.\d{1,3}){3}$/.test(ip.trim())) return null;
  const octets = ip.trim().split(".").map(Number);
  if (octets.some((value) => value > 255)) return null;
  return octets.reduce((value, octet) => value * 256 + octet, 0);
}
const ipText = (value) => [24, 16, 8, 0].map((shift) => (value >>> shift) & 255).join(".");
function interval(low, high = low) {
  const start = ipNumber(low), end = ipNumber(high);
  return start !== null && end !== null && start <= end ? {start, end} : null;
}
export function subtractDhcpExclusions(ranges, exclusions) {
  let remaining = ranges;
  for (const excluded of exclusions) {
    remaining = remaining.flatMap((range) => {
      if (excluded.end < range.start || excluded.start > range.end) return [range];
      const parts = [];
      if (excluded.start > range.start) parts.push({start: range.start, end: excluded.start - 1});
      if (excluded.end < range.end) parts.push({start: excluded.end + 1, end: range.end});
      return parts;
    });
  }
  return remaining.map(({start, end}) => ({low: ipText(start), high: ipText(end)}));
}

export function juniperPoolRanges(inet) {
  const configuredRanges = array(inet.range).map((range) => ({name: range.name, low: range.low, high: range.high}));
  const excludedRangeEntries = array(inet["excluded-range"]).map((range) => ({name: range.name, low: range.low, high: range.high}));
  const excludeRanges = array(inet["excluded-address"]).map((entry) => typeof entry === "string" ? entry : entry.name);
  const ranges = configuredRanges.map(({low, high}) => interval(low, high ?? ""));
  const exclusions = [...excludeRanges.map((ip) => interval(ip)), ...excludedRangeEntries.map(({low, high}) => interval(low, high ?? ""))];
  const rangeDataValid = ranges.every(Boolean) && exclusions.every(Boolean);
  const usableRanges = rangeDataValid ? subtractDhcpExclusions(ranges, exclusions) : [];
  const only = configuredRanges.length === 1 && rangeDataValid ? configuredRanges[0] : null;
  return {configuredRanges, excludedRangeEntries, excludeRanges, usableRanges, rangeDataValid,
    startAddress: only?.low || "", endAddress: only?.high || "",
    range: rangeDataValid ? (usableRanges.map(({low, high}) => `${low}-${high}`).join(", ") || (configuredRanges.length ? "No IP remaining in range" : "No range specified")) : "Incomplete IP range data"};
}

export function ciscoPoolRanges(network, excluded) {
  const address = ipNumber(network.number);
  const mask = ipNumber(network.mask);
  if (address === null || mask === null) return {rangeDataValid: false, usableRanges: [], startAddress: "", endAddress: "", range: "Incomplete Network data"};
  const start = ((address & mask) >>> 0) + 1;
  const end = (((address & mask) | (~mask >>> 0)) >>> 0) - 1;
  const usableRanges = start <= end ? subtractDhcpExclusions([{start, end}], excluded) : [];
  const only = usableRanges.length === 1 ? usableRanges[0] : null;
  return {rangeDataValid: true, usableRanges, startAddress: only?.low || "", endAddress: only?.high || "",
    range: usableRanges.map(({low, high}) => `${low}-${high}`).join(", ") || "No IP remaining in range"};
}
