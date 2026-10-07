function ensureArray(value) {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

function hasOwn(object, key) {
  return object !== null && typeof object === "object"
    && Object.prototype.hasOwnProperty.call(object, key);
}

function first(value) {
  return ensureArray(value)[0] || null;
}

function parseAddress(entry) {
  const base = {
    key: `address:${entry?.name || ""}`,
    kind: "address",
    name: entry?.name || "",
    description: entry?.description || "",
    editable: false,
    deletable: true,
    ip: "",
  };

  if (hasOwn(entry, "ip-prefix")) {
    const value = entry?.["ip-prefix"] || "";
    return { ...base, type: "IP Prefix", value, ip: value, editable: true };
  }

  const dns = first(entry?.["dns-name"]);
  if (dns) {
    const details = [];
    if (hasOwn(dns, "ipv4-only")) details.push("IPv4 only");
    if (hasOwn(dns, "ipv6-only")) details.push("IPv6 only");
    if (dns?.["dns-query-interval"] !== undefined) {
      details.push(`query ${dns["dns-query-interval"]}s`);
    }
    const value = `${dns?.name || "-"}${details.length ? ` (${details.join(", ")})` : ""}`;
    return { ...base, type: "DNS Name", value };
  }

  const wildcard = first(entry?.["wildcard-address"]);
  if (wildcard) {
    return { ...base, type: "Wildcard Address", value: wildcard?.name || "-" };
  }

  const range = first(entry?.["range-address"]);
  if (range) {
    const low = range?.name || "-";
    const high = range?.to?.["range-high"] || "-";
    return { ...base, type: "IPv4 Range", value: `${low} - ${high}` };
  }

  const addressRange = first(entry?.["address-range"]);
  if (addressRange) {
    const low = addressRange?.name || "-";
    const high = addressRange?.to?.["range-high"] || "-";
    return { ...base, type: "Prefix Range", value: `${low} - ${high}` };
  }

  return { ...base, type: "Unknown", value: "Unsupported format" };
}

function parseAddressSet(entry) {
  const addresses = ensureArray(entry?.address)
    .map((member) => member?.name)
    .filter(Boolean);
  const nestedSets = ensureArray(entry?.["address-set"])
    .map((member) => member?.name)
    .filter(Boolean)
    .map((name) => `Set: ${name}`);
  return {
    key: `address-set:${entry?.name || ""}`,
    kind: "address-set",
    name: entry?.name || "",
    description: entry?.description || "",
    type: "Address Set",
    value: [...addresses, ...nestedSets].join(", ") || "-",
    editable: false,
    deletable: false,
    ip: "",
  };
}

function globalAddressBook(result) {
  const books = ensureArray(
    result?.payload?.data?.configuration?.security?.["address-book"]
  );
  return books.find((book) => book?.name === "global") || null;
}

export function parseJuniperAddressBook(result) {
  try {
    const global = globalAddressBook(result);
    if (!global) return [];
    return [
      ...ensureArray(global.address).map(parseAddress),
      ...ensureArray(global["address-set"]).map(parseAddressSet),
    ];
  } catch {
    return null;
  }
}

export function parseJuniperAddressBookNames(result) {
  const rows = parseJuniperAddressBook(result);
  if (!rows) return [];
  return [...new Set(rows.map((row) => row.name).filter(Boolean))];
}
