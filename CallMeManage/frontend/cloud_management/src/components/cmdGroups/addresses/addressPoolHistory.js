function asList(value) {
  if (value === undefined || value === null || value === "") return [];
  return Array.isArray(value) ? value : [value];
}

export function describeNatPoolChange(parameters = {}) {
  const starts = asList(parameters.address_starts).length
    ? asList(parameters.address_starts)
    : asList(parameters.start);
  const ends = asList(parameters.address_ends).length
    ? asList(parameters.address_ends)
    : asList(parameters.end);
  const ranges = starts.map((start, index) => (
    `${start}${ends[index] ? ` - ${ends[index]}` : ""}`
  ));
  const rangeText = ranges.length ? ` (${ranges.join(", ")})` : "";
  const maskText = parameters.netmask ? `, Netmask ${parameters.netmask}` : "";
  return `${parameters.replace_name ? "Edit" : "Create"} NAT Pool "${parameters.name || "-"}"${rangeText}${maskText}`;
}

export function describeNatPoolRemoval(parameters = {}) {
  return `Delete NAT Pool "${parameters.name || "-"}"`;
}
