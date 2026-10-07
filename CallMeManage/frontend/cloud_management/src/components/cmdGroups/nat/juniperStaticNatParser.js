import {proxyArpInterfaceForAddress} from "./proxyArpBindings.js";

function ensureArray(value) {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

function staticRuleSets(result) {
  return ensureArray(result?.payload?.data?.configuration?.security?.nat?.static?.["rule-set"]);
}

// Rule name is unique only inside its rule-set, not across the whole device.
// Use both list keys so equal names in different zones never select each other.
export function juniperStaticNatKey(row) {
  return `${row?.ruleSet || ""}|${row?.name || ""}`;
}

// Static NAT table intentionally hides legacy static-NAT-with-port rules, but
// their rule-set and context still exist on the device. Keep the real count so
// delete/edit logic never treats a partially hidden rule-set as empty.
export function parseJuniperStaticNat(result) {
  const rows = [];
  for (const ruleSet of staticRuleSets(result)) {
    const rules = ensureArray(ruleSet?.rule);
    for (const rule of rules) {
      const match = rule?.["static-nat-rule-match"];
      if (match?.["destination-port"]) continue;
      const globalIp = match?.["destination-address"]?.["dst-addr"] || "";
      rows.push({
        name: rule?.name || "",
        ruleSet: ruleSet?.name || "",
        fromZone: ruleSet?.from?.zone || "",
        localIp: rule?.then?.["static-nat"]?.prefix?.["addr-prefix"] || "",
        globalIp,
        ruleSetRuleCount: rules.length,
        proxyArpInterface: proxyArpInterfaceForAddress(result, globalIp),
      });
    }
  }
  return rows;
}

// Preserve every rule-set context, including sets whose rules are all hidden
// from the Static NAT table. Junos permits only one static NAT rule-set per
// from-zone, so create must reuse this actual brownfield identity.
export function parseJuniperStaticRuleSets(result) {
  return staticRuleSets(result).map((ruleSet) => {
    const rules = ensureArray(ruleSet?.rule);
    return {
      ruleSet: ruleSet?.name || "",
      fromZone: ruleSet?.from?.zone || "",
      ruleNames: rules.map((rule) => rule?.name).filter(Boolean),
      ruleCount: rules.length,
    };
  }).filter((context) => context.ruleSet && context.fromZone);
}
