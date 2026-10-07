function ensureArray(value) {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

function textValue(value) {
  if (typeof value === "string" || typeof value === "number") return String(value);
  return value?.name || "";
}

function sourceRuleSets(result) {
  return ensureArray(
    result?.payload?.data?.configuration?.security?.nat?.source?.["rule-set"],
  );
}

// Source NAT rule names are keys only inside their rule-set. Brownfield devices
// commonly keep several rules in one set, so the row identity must contain both.
export function juniperSourceNatKey(row) {
  return `${row?.ruleSet || ""}|${row?.name || ""}`;
}

export function parseJuniperSourceNat(result) {
  const rows = [];
  for (const ruleSet of sourceRuleSets(result)) {
    const rules = ensureArray(ruleSet?.rule);
    const fromZones = ensureArray(ruleSet?.from?.zone).map(textValue).filter(Boolean);
    const toZones = ensureArray(ruleSet?.to?.zone).map(textValue).filter(Boolean);
    for (const rule of rules) {
      const sourceNat = rule?.then?.["source-nat"];
      if (!sourceNat) continue;
      const sourceAddresses = ensureArray(rule?.["src-nat-rule-match"]?.["source-address"])
        .map(textValue)
        .filter(Boolean);
      const isPool = Boolean(sourceNat.pool);
      rows.push({
        name: textValue(rule?.name),
        ruleSet: textValue(ruleSet?.name),
        ruleSetRuleCount: rules.length,
        mode: isPool ? "pool" : "interface",
        target: isPool ? textValue(sourceNat.pool?.["pool-name"]) : toZones.join(", "),
        overload: true,
        fromZones,
        toZones,
        toZone: toZones[0] || "",
        sourceAddresses: sourceAddresses.length ? sourceAddresses : ["0.0.0.0/0"],
      });
    }
  }
  return rows;
}
