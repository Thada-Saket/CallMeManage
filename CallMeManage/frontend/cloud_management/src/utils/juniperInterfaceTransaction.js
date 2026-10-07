const items = (value) => value == null ? [] : Array.isArray(value) ? value : [value];
const step = (command, parameters) => ({command, parameters});

function networkKey(cidr) {
  if (typeof cidr !== "string") return null;
  const parts = cidr.trim().split("/");
  if (parts.length !== 2 || !/^\d+$/.test(parts[1])) return null;
  const prefix = Number(parts[1]);
  const octets = parts[0].split(".");
  if (prefix < 0 || prefix > 32 || octets.length !== 4 || octets.some(value => !/^\d+$/.test(value) || Number(value) > 255)) return null;
  const ip = octets.reduce((value, octet) => (value * 256 + Number(octet)) >>> 0, 0);
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return `${(ip & mask) >>> 0}/${prefix}`;
}

export function juniperInterfacePoolCleanup({configuration, binding, pools, requirePool = false}) {
  if (!configuration?.interfaces || !Array.isArray(pools)) throw new Error("Incomplete interface or DHCP pool data; configuration unchanged");
  const parentName = `${binding.interface_type}${binding.interface_id}`;
  const fullName = `${parentName}.${binding.unit}`;
  const interfaces = items(configuration.interfaces.interface);
  const parent = interfaces.find(entry => entry.name === parentName);
  const unit = items(parent?.unit).find(entry => String(entry.name) === String(binding.unit));
  if (!unit) throw new Error("unit not found in latest configuration; please reload");
  const keys = new Set(items(unit.family?.inet?.address).map(entry => {
    const key = networkKey(entry.name);
    if (!key) throw new Error("Incomplete static address data; configuration unchanged");
    return key;
  }));
  const serverMembers = new Set(items(configuration.system?.services?.["dhcp-local-server"]?.group)
    .flatMap(group => items(group.interface).map(entry => entry.name)));
  const keyedPools = pools.map(pool => {
    const key = networkKey(pool.network);
    if (!key || !pool.name) throw new Error("Incomplete DHCP pool name or network data; configuration unchanged");
    return {pool, key};
  });
  const matched = keyedPools.filter(entry => keys.has(entry.key));
  if ((requirePool || serverMembers.has(fullName)) && pools.length && !matched.length) {
    throw new Error("DHCP Server is bound but cannot match pool with existing IP; cannot delete interface or change mode");
  }
  const sharedKeys = new Set();
  for (const iface of interfaces) for (const sibling of items(iface.unit)) {
    const name = `${iface.name}.${sibling.name}`;
    if (name === fullName || !serverMembers.has(name)) continue;
    for (const address of items(sibling.family?.inet?.address)) {
      const key = networkKey(address.name);
      if (!key) throw new Error("Incomplete IP data for other DHCP Server members; pool not deleted");
      sharedKeys.add(key);
    }
  }
  return [...new Map(matched.filter(entry => !sharedKeys.has(entry.key)).map(entry => [entry.pool.name, entry.pool])).values()];
}

export function juniperRelayRemovalSteps({configuration, binding}) {
  const fullName = `${binding.interface_type}${binding.interface_id}.${binding.unit}`;
  const safeId = fullName.replaceAll("/", "-").replaceAll(".", "-");
  return items(configuration?.["forwarding-options"]?.["dhcp-relay"]?.group)
    .filter(group => items(group.interface).some(entry => entry.name === fullName))
    .map(group => group.name === `RELAY-${safeId}` && items(group.interface).length === 1
      && group["active-server-group"]?.["active-server-group"] === `SG-${safeId}`
      ? step("remove_dhcp_relay_interface", binding)
      : step("remove_dhcp_relay_member", {...binding, group: group.name}));
}

// Junos ผูก OSPF ด้วยชื่อ logical interface โดยตรง ถ้าลบ unit/tunnel โดยไม่ถอด
// protocols/ospf/area/interface ก่อน commit จะถูกปฏิเสธหรือเหลือ reference ค้าง
// สร้าง minimal delta เฉพาะชื่อเป้าหมาย ไม่ replace OSPF ทั้งก้อน เพื่อรักษา
// Brownfield options และ interface อื่นใน area เดิมไว้ครบ
export function juniperOspfRemovalSteps({configuration, interfaceName, interfaceType, interfaceId}) {
  const commands = [];
  const seenAreas = new Set();
  for (const area of items(configuration?.protocols?.ospf?.area)) {
    if (!items(area?.interface).some((entry) => entry?.name === interfaceName)) continue;
    const areaName = area?.name;
    if (areaName === undefined || areaName === null || String(areaName).trim() === "") {
      throw new Error("Incomplete OSPF area data; interface not deleted");
    }
    const areaKey = String(areaName);
    if (seenAreas.has(areaKey)) continue;
    seenAreas.add(areaKey);
    commands.push(step("remove_ospf_interface", {
      area: areaName,
      interface_type: interfaceType,
      interface_id: interfaceId,
    }));
  }
  return commands;
}

// Proxy ARP อ้าง logical interface เป็น key โดยตรงและ Junos ไม่ยอมให้ unit หาย
// ขณะที่ binding เหล่านี้ยังอยู่ ลบเฉพาะ address children ใต้ interface เป้าหมาย
// ไม่แตะ NAT rules หรือ Proxy ARP ของ interface อื่น
export function juniperProxyArpRemovalSteps({configuration, interfaceName, interfaceType, interfaceId}) {
  const commands = [];
  for (const binding of items(configuration?.security?.nat?.["proxy-arp"]?.interface)) {
    if (binding?.name !== interfaceName) continue;
    for (const address of items(binding?.address)) {
      if (typeof address?.name !== "string" || !address.name.trim()) {
        throw new Error("Incomplete NAT Proxy ARP data; interface not deleted");
      }
      commands.push(step("remove_nat_proxy_arp", {
        interface_type: interfaceType,
        interface_id: interfaceId,
        address: address.name,
      }));
    }
  }
  return commands;
}

export function juniperInterfaceSaveSteps({interfaceStep, binding, originalDhcp, dhcpAction, configuration, resetMtu = false, poolCleanup}) {
  const commands = [];
  const fullName = `${binding.interface_type}${binding.interface_id}.${binding.unit}`;
  const serverGroups = items(configuration?.system?.services?.["dhcp-local-server"]?.group)
    .filter(group => items(group.interface).some(entry => entry.name === fullName));
  const relayRemovals = juniperRelayRemovalSteps({configuration, binding});
  const oldServer = serverGroups.length > 0 || originalDhcp?.mode === "server";
  const oldRelay = relayRemovals.length > 0 || originalDhcp?.mode === "relay";
  const newServer = dhcpAction?.command === "set_dhcp_pool";
  const newRelay = dhcpAction?.command === "set_dhcp_relay";
  if (oldRelay && !newRelay) {
    commands.push(...(relayRemovals.length ? relayRemovals : [step("remove_dhcp_relay_interface", binding)]));
  } else if (oldRelay && newRelay && relayRemovals.some(entry => entry.command === "remove_dhcp_relay_member")) {
    // Move external/shared memberships to the application's per-interface group.
    commands.push(...relayRemovals);
  } else if (oldRelay && newRelay && originalDhcp.relayIp && originalDhcp.relayIp !== dhcpAction.parameters.helper_ip) {
    commands.push(step("remove_dhcp_relay", {...binding, helper_ip: originalDhcp.relayIp}));
  }
  if (oldServer && !newServer) {
    commands.push(...(serverGroups.length ? serverGroups.map(group => step("remove_dhcp_server_interface", {...binding, group: group.name}))
      : [step("remove_dhcp_server_interface", binding)]));
    commands.push(step("remove_dns_server_interface", binding));
    if (poolCleanup === undefined && originalDhcp?.pool?.name) commands.push(step("remove_dhcp_pool", {name: originalDhcp.pool.name}));
  } else if (oldServer && newServer && !dhcpAction.dnsProxyBinding) {
    commands.push(step("remove_dns_server_interface", binding));
  }
  if (interfaceStep.command === "set_interface_l3_none" && !oldServer
      && items(configuration?.system?.services?.dns?.["dns-proxy"]?.interface).some(entry => entry.name === fullName)) {
    commands.push(step("remove_dns_server_interface", binding));
  }
  if (poolCleanup && (oldServer || ["set_interface_ip_dhcp", "set_interface_l3_none"].includes(interfaceStep.command))) {
    for (const pool of poolCleanup) {
      if (!newServer || networkKey(pool.network) !== networkKey(dhcpAction.parameters.network)) {
        commands.push(step("remove_dhcp_pool", {name: pool.name}));
      }
    }
  }
  if (resetMtu) commands.push(step("remove_interface_mtu", {
    interface_type: binding.interface_type, interface_id: binding.interface_id,
  }));
  const parent = items(configuration?.interfaces?.interface).find(entry => entry.name === `${binding.interface_type}${binding.interface_id}`);
  const unit = items(parent?.unit).find(entry => String(entry.name) === String(binding.unit));
  if (interfaceStep.command !== "apply_interface_to_vlan" && interfaceStep.command !== "set_interface_l3_none"
      && unit?.family && Object.hasOwn(unit.family, "ethernet-switching")) {
    commands.push(step("remove_switchport", binding));
  }
  commands.push(interfaceStep);
  if (dhcpAction) {
    commands.push(step(dhcpAction.command, dhcpAction.parameters));
    if (dhcpAction.followUp) commands.push(dhcpAction.followUp);
    if (dhcpAction.dnsProxyBinding) commands.push(step("set_dns_server_interface", dhcpAction.dnsProxyBinding));
  }
  return commands;
}

export function juniperInterfaceDeleteSteps({configuration, params, pool, pools}) {
  if (!configuration?.interfaces) throw new Error("Failed to read Interface configuration; interface not deleted");
  const parentName = `${params.interface_type}${params.interface_id}`;
  const fullName = `${parentName}.${params.unit}`;
  const parent = items(configuration.interfaces.interface).find((entry) => entry.name === parentName);
  const units = items(parent?.unit);
  if (!units.some((entry) => String(entry.name) === String(params.unit))) {
    throw new Error("unit not found in latest configuration; please reload");
  }
  const binding = {interface_type: params.interface_type, interface_id: params.interface_id, unit: params.unit};
  const commands = [];
  const matches = (entry) => entry?.name === fullName;
  for (const group of items(configuration.system?.services?.["dhcp-local-server"]?.group)) {
    if (items(group.interface).some(matches)) commands.push(step("remove_dhcp_server_interface", {...binding, group: group.name}));
  }
  for (const group of items(configuration["forwarding-options"]?.["dhcp-relay"]?.group)) {
    if (items(group.interface).some(matches)) commands.push(step("remove_dhcp_relay_member", {...binding, group: group.name}));
  }
  if (items(configuration.system?.services?.dns?.["dns-proxy"]?.interface).some(matches)) {
    commands.push(step("remove_dns_server_interface", binding));
  }
  commands.push(...juniperProxyArpRemovalSteps({
    configuration,
    interfaceName: fullName,
    interfaceType: params.interface_type,
    interfaceId: `${params.interface_id}.${params.unit}`,
  }));
  for (const zone of items(configuration.security?.zones?.["security-zone"])) {
    if (items(zone.interfaces).some(matches)) commands.push(step("remove_zone_member", {
      interface_type: params.interface_type, interface_id: `${params.interface_id}.${params.unit}`, zone_name: zone.name,
    }));
  }
  commands.push(...juniperOspfRemovalSteps({
    configuration,
    interfaceName: fullName,
    interfaceType: params.interface_type,
    interfaceId: `${params.interface_id}.${params.unit}`,
  }));
  for (const entry of pools ?? (pool ? [pool] : [])) {
    commands.push(step("remove_dhcp_pool", {name: entry.name}));
  }
  const vlanNames = parentName === "irb" ? items(configuration.vlans?.vlan)
    .filter(entry => entry["l3-interface"] === fullName).map(entry => entry.name) : [];
  if (vlanNames.some(name => typeof name !== "string" || !name.trim())) {
    throw new Error("Incomplete VLAN name data bound to irb; interface not deleted");
  }
  commands.push(step("remove_interface_unit", {...binding, ...(vlanNames.length ? {vlan_names: [...new Set(vlanNames)]} : {})}));
  const hasSibling = units.some((entry) => String(entry.name) !== String(params.unit) && String(entry.name) !== "32767");
  if (params.unit !== 0 && parentName !== "irb" && "vlan-tagging" in parent && !hasSibling) {
    commands.push(step("remove_vlan_tagging", {interface_type: params.interface_type, interface_id: params.interface_id}));
  }
  return commands;
}
