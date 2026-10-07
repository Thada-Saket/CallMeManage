function ensureArray(value) {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

function displayIPv4Host(value) {
  const text = String(value ?? "").trim();
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/32$/.exec(text);
  if (!match || match.slice(1).some((part) => Number(part) > 255)) return text;
  return match.slice(1).map(Number).join(".");
}

function prefixLengthToNetmask(value) {
  const prefix = Number(value);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return "";
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return [24, 16, 8, 0].map((shift) => (mask >>> shift) & 0xff).join(".");
}

export function parseJuniperPools(result) {
  const pools = ensureArray(
    result?.payload?.data?.configuration?.security?.nat?.source?.pool
  );
  return pools.map((pool) => {
    const ranges = ensureArray(pool?.address).map((address) => {
      const rawStart = address?.name || "";
      const rawEnd = address?.to?.ipaddr || "";
      return {
        start: displayIPv4Host(rawStart),
        startKey: rawStart,
        end: displayIPv4Host(rawEnd),
      };
    });
    const firstRange = ranges[0] || { start: "", startKey: "", end: "" };
    return {
      name: pool?.name || "",
      // Junos canonicalizes a host to /32 when reading configuration back.
      // The form accepts an address (without prefix), but Edit must retain the
      // original list key so the backend can target the existing entry.
      start: firstRange.start,
      startKey: firstRange.startKey,
      end: firstRange.end,
      ranges,
      netmask: "",
    };
  });
}

export function parseAddressPools(result) {
  if (result?.vendor === "juniper") {
    try {
      return parseJuniperPools(result);
    } catch {
      return null;
    }
  }
  try {
    const pool = result?.payload?.data?.native?.ip?.nat?.pool;
    if (!pool) return [];
    return ensureArray(pool).map((entry) => {
      const hasPrefixLength = entry?.["prefix-length"] !== undefined
        && entry?.["prefix-length"] !== null
        && entry?.["prefix-length"] !== "";
      return {
        name: entry?.id || "",
        start: entry?.["start-address"] || "",
        end: entry?.["end-address"] || "",
        netmask: entry?.netmask || prefixLengthToNetmask(entry?.["prefix-length"]),
        maskMode: hasPrefixLength ? "prefix-length" : "netmask",
      };
    });
  } catch {
    return null;
  }
}
