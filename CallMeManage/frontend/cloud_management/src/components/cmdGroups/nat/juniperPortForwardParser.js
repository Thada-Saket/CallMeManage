import { proxyArpInterfaceForAddress } from "./proxyArpBindings.js";

function ensureArray(value) {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

export function parseJuniperPortForwards(result) {
  const dest = result?.payload?.data?.configuration?.security?.nat?.destination;
  const poolByName = {};
  for (const pool of ensureArray(dest?.pool)) {
    if (pool?.name) poolByName[pool.name] = pool;
  }

  const rows = [];
  for (const rs of ensureArray(dest?.["rule-set"])) {
    const rules = ensureArray(rs?.rule);
    for (const rule of rules) {
      const match = rule?.["dest-nat-rule-match"];
      const poolName = rule?.then?.["destination-nat"]?.pool?.["pool-name"] || "";
      const pool = poolByName[poolName];
      const globalPorts = ensureArray(match?.["destination-port"])
        .flatMap((entry) => ensureArray(
          entry && typeof entry === "object" ? entry.name : entry,
        ))
        .filter((port) => port !== undefined && port !== null && port !== "");
      // UI model edits one destination port per rule.  Old versions could
      // accidentally append ports; use the last configured value as the
      // visible/current value but retain every key so Edit can remove the
      // complete stale list atomically.
      const globalPort = globalPorts.at(-1);
      const localPort = pool?.address?.port;

      // Destination NAT ที่ไม่มี port ไม่ใช่ Port Forwarding ห้ามนำมาแสดงหรือเปิด
      // ให้ Edit/Delete จากหน้านี้ ต้องมี port ครบทั้ง match และ translated pool
      if (globalPort === undefined || globalPort === null || globalPort === ""
          || localPort === undefined || localPort === null || localPort === "") continue;

      const globalIp = match?.["destination-address"]?.["dst-addr"] || "";
      rows.push({
        name: rule?.name || "",
        ruleSet: rs?.name || "",
        poolName,
        fromZone: rs?.from?.zone || "",
        // รวม hidden non-port rules ด้วย เพื่อไม่คิดผิดว่าแถวนี้เป็น rule สุดท้าย
        ruleSetRuleCount: rules.length,
        protocol: "",
        localIp: pool?.address?.ipaddr || "",
        localPort,
        globalIp,
        globalPort,
        globalPorts,
        proxyArpInterface: proxyArpInterfaceForAddress(result, globalIp),
      });
    }
  }
  return rows;
}

// เก็บ context แม้ rule-set จะมีแต่ Destination NAT แบบไม่มี port ซึ่งไม่ขึ้นตาราง
// เพราะมันยังครอง from-zone และต้องถูกใช้ซ้ำเมื่อสร้าง/ย้าย Port Forward
export function parseJuniperDestinationRuleSets(result) {
  const ruleSets = ensureArray(
    result?.payload?.data?.configuration?.security?.nat?.destination?.["rule-set"],
  );
  return ruleSets.filter((rs) => rs?.name).map((rs) => {
    const rules = ensureArray(rs?.rule);
    return {
      ruleSet: rs.name,
      fromZone: rs?.from?.zone || "",
      ruleNames: rules.map((rule) => rule?.name).filter(Boolean),
      ruleCount: rules.length,
    };
  });
}
