// ไล่ "object จริงทุกตัว" ที่ Security Profile แต่ละแถวประกอบขึ้นจากข้อมูลบนอุปกรณ์
//
// เหตุผลที่ต้องมี: ชื่ออย่าง `{name}-IKEV2-PROP` เป็นแค่ตัวช่วยตอน "สร้างใหม่" ให้ผู้ใช้ไม่ต้องตั้งชื่อ
// object ย่อยเอง - ของที่มีอยู่แล้วบนอุปกรณ์ตั้งชื่อตามใจผู้ตั้ง แถวเหล่านั้นต้องแก้/ลบได้เท่ากับของที่
// ระบบสร้าง (ผู้ใช้ยืนยัน 21 ก.ย. 2026) จึงต้องรู้ชื่อจริงของทุก object แล้วส่งชื่อจริงไปให้ backend
// ไม่ derive จากชื่อที่แสดง
//
// ผลลัพธ์ต่อแถว (`real`):
//   objects   ชื่อ object จริงแต่ละชั้น (null = ไม่ผูกกับ profile นี้)
//   sections  ส่วนไหนของฟอร์มแก้ได้ (editable) ถ้าไม่ได้บอกเหตุผล - ส่วนที่แก้ไม่ได้ยังแสดงค่าจริง
//   raw       ค่าจริงบนอุปกรณ์ทุกค่า (ไม่ผ่านการ map) ไว้แสดงเมื่อค่านั้นอยู่นอกตัวเลือกของฟอร์ม
//   removal   พารามิเตอร์ของ remove_security_profile_objects + รายการที่ "จะไม่ลบ" พร้อมเหตุผล
//
// หลักที่ใช้ทั้งไฟล์: object ที่ profile อื่นอ้างอยู่ด้วย (shared) ห้ามลบและห้ามแก้ผ่านแถวนี้ -
// ผลกระทบไปตกที่ profile อื่นโดยที่ผู้ใช้ไม่รู้ ต้องบอกว่าใช้ร่วมกับอะไรแทนที่จะเดาว่าเจ้าของคือใคร

function ensureArray(value) {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

// Cisco เก็บ enum เป็นชื่อ element ว่าง (<aes-cbc-256/>) -> object ที่ key คือค่า
function keysOf(container) {
  if (!container || typeof container !== "object") return [];
  return Object.keys(container);
}

const ok = () => ({ editable: true, reason: "" });
const blocked = (reason) => ({ editable: false, reason });

const list = (names) => names.join(", ");

// =====================================================================================
// Cisco
// =====================================================================================

export function resolveCiscoProfileObjects(crypto) {
  const ipsecProfiles = ensureArray(crypto?.ipsec?.profile);
  const transformSets = ensureArray(crypto?.ipsec?.["transform-set"]);
  const ikev2Profiles = ensureArray(crypto?.ikev2?.profile);
  const policies = ensureArray(crypto?.ikev2?.policy);
  const proposals = ensureArray(crypto?.ikev2?.proposal);
  const keyrings = ensureArray(crypto?.ikev2?.keyring);

  const byName = (items, key = "name") => Object.fromEntries(items.filter((i) => i?.[key]).map((i) => [i[key], i]));
  const transformSetByTag = byName(transformSets, "tag");
  const ikev2ByName = byName(ikev2Profiles);
  const policyByName = byName(policies);
  const proposalByName = byName(proposals);
  const keyringByName = byName(keyrings);

  const keyringOf = (ikeProfile) => ikeProfile?.keyring?.local?.name || null;
  const usersOf = (items, pick, target, selfName) =>
    items.filter((item) => item?.name !== selfName && pick(item) === target).map((item) => item.name);

  return function resolve(ipsecProfile) {
    const fullName = ipsecProfile?.name || "";
    const base = fullName.replace(/-IPSEC-PROFILE$/, "") || fullName;
    const set = ipsecProfile?.set || {};
    const tsName = ensureArray(set["transform-set"])[0] || null;
    const ikeProfName = set["ikev2-profile"] || null;
    const ts = tsName ? transformSetByTag[tsName] : null;
    const ikeProfile = ikeProfName ? ikev2ByName[ikeProfName] : null;

    // ---- peer: ikev2 profile match identity remote address ----
    const remote = ikeProfile?.match?.identity?.remote || {};
    const v4 = ensureArray(remote.address?.ipv4);
    const peerIps = v4.map((entry) => entry?.["ipv4-address"]).filter(Boolean);
    const otherIdentity = ["any", "email", "fqdn", "key-ids", "key-id"].filter((k) => remote[k] !== undefined);
    const hasV6 = ensureArray(remote.address?.["ipv6-prefix"]).length > 0;
    const isHostMask = (v4[0]?.["ipv4-mask"] || "255.255.255.255") === "255.255.255.255";

    // ---- keyring peer ที่เป็นของ profile นี้ (จับคู่ด้วย address เท่านั้น ไม่เดา) ----
    const keyringName = keyringOf(ikeProfile);
    const keyring = keyringName ? keyringByName[keyringName] : null;
    const peers = ensureArray(keyring?.peer);
    const ownPeer = peers.find((peer) => peerIps.length === 1 && peer?.address?.ipv4?.["ipv4-address"] === peerIps[0]) || null;
    const pskStructure = ownPeer?.["pre-shared-key"] || {};
    const hasSharedPsk = Object.prototype.hasOwnProperty.call(pskStructure, "key");
    const hasLocalPsk = Object.prototype.hasOwnProperty.call(pskStructure?.["local-option"] || {}, "key");
    const hasRemotePsk = Object.prototype.hasOwnProperty.call(pskStructure?.["remote-option"] || {}, "key");
    // รักษารูปแบบ PSK เดิมของ brownfield: `pre-shared-key X`, `... local X` และ
    // `... remote X` มี path ใน YANG คนละแบบ แม้ UI จะใช้ช่อง Change Key เดียวกัน
    const pskType = hasSharedPsk ? "key" : hasLocalPsk && !hasRemotePsk ? "local" : hasRemotePsk && !hasLocalPsk ? "remote" : null;

    // ---- IKEv2 policy/proposal: profile ไม่ได้อ้างถึงโดยตรง (Cisco ใช้ policy กลางของอุปกรณ์) ----
    const namedPolicy = policyByName[`${base}-IKEV2-POLICY`] || null;
    let policy = namedPolicy;
    let policyLink = namedPolicy ? "name" : null;
    if (!policy && policies.length === 1) {
      policy = policies[0];
      policyLink = "only";
    }
    const proposalNames = ensureArray(policy?.proposal?.proposals);
    const proposalName = proposalNames.length === 1 ? proposalNames[0] : null;
    const proposal = proposalName ? proposalByName[proposalName] : null;

    // ---- ใครใช้ object เหล่านี้ร่วมกับเรา ----
    const otherTsUsers = tsName ? usersOf(ipsecProfiles, (p) => ensureArray(p?.set?.["transform-set"])[0], tsName, fullName) : [];
    const otherIkeUsers = ikeProfName ? usersOf(ipsecProfiles, (p) => p?.set?.["ikev2-profile"], ikeProfName, fullName) : [];
    const otherKeyringUsers = keyringName ? usersOf(ikev2Profiles, keyringOf, keyringName, ikeProfName) : [];
    const otherProposalUsers = proposalName
      ? policies.filter((p) => p?.name !== policy?.name && ensureArray(p?.proposal?.proposals).includes(proposalName)).map((p) => p.name)
      : [];
    // policy ที่อนุมานว่าเป็น "ตัวเดียวของอุปกรณ์" ใช้ร่วมกับทุก profile ที่เหลือโดยปริยาย
    const otherProfilesOnPolicy = policyLink === "only" ? ipsecProfiles.filter((p) => p?.name !== fullName).map((p) => p.name) : [];

    // ---- ค่าจริง ----
    const raw = {
      ikev2Encryption: keysOf(proposal?.encryption),
      ikev2Integrity: keysOf(proposal?.integrity).length ? keysOf(proposal?.integrity) : keysOf(proposal?.prf),
      ikev2Group: keysOf(proposal?.group),
      ipsecEncryption: ts?.esp || null,
      ipsecKeySize: ts?.["key-bit"] ? String(ts["key-bit"]) : null,
      ipsecIntegrity: ts?.["esp-hmac"] || null,
      pfsGroup: set?.pfs?.group || null,
    };

    // ---- ส่วนไหนแก้ได้ ----
    const sections = { pfs: ok() };
    if (!ikeProfile) sections.peer = blocked("This profile is not bound to an IKEv2 profile, so there is no Peer to edit");
    else if (otherIkeUsers.length) sections.peer = blocked(`IKEv2 profile ${ikeProfName} is shared with ${list(otherIkeUsers)} - editing here will affect those profiles`);
    else if (v4.length !== 1 || hasV6 || otherIdentity.length) sections.peer = blocked("This profile matches Peer with criteria other than a single IPv4 (multiple values/FQDN/email/...) and cannot be edited via this form");
    else if (!isHostMask) sections.peer = blocked("This profile matches Peer as a network range, not a single IPv4, and cannot be edited via this form");
    else if (keyring && !ownPeer) sections.peer = blocked("Cannot find peer for this Profile in keyring (no matching address) - editing one side will cause mismatch with keyring");
    else sections.peer = ok();

    if (!keyring) sections.psk = blocked("This profile does not use a keyring");
    else if (!ownPeer) sections.psk = blocked("Cannot find peer for this Profile in keyring to edit PSK");
    else if (!pskType) sections.psk = blocked("This peer uses separate local and remote keys, so one PSK field cannot safely replace both");
    else sections.psk = ok();

    if (!policy) sections.ikev2 = blocked("No IKEv2 policy is bound to this Profile (device has multiple policies and Profile does not reference any)");
    else if (!proposalName) sections.ikev2 = blocked(proposalNames.length > 1 ? `policy ${policy.name} references multiple proposals (${list(proposalNames)})` : `policy ${policy.name} has no proposals`);
    else if (!proposal) sections.ikev2 = blocked(`Cannot find proposal ${proposalName} on device`);
    else if (otherProposalUsers.length) sections.ikev2 = blocked(`proposal ${proposalName} is shared with policy ${list(otherProposalUsers)}`);
    else if (otherProfilesOnPolicy.length) sections.ikev2 = blocked(`IKEv2 policy ${policy.name} is the only policy on device and shared with ${list(otherProfilesOnPolicy)} - editing here will affect those profiles`);
    else sections.ikev2 = ok();

    if (!ts) sections.ipsec = blocked(tsName ? `Cannot find transform-set ${tsName} on device` : "This profile is not bound to a transform-set");
    else if (otherTsUsers.length) sections.ipsec = blocked(`transform-set ${tsName} is shared with ${list(otherTsUsers)} - editing here will affect those profiles`);
    else if (!ts.esp) sections.ipsec = blocked("This transform-set does not use ESP (e.g. AH) and cannot be edited via this form");
    else sections.ipsec = ok();

    // ---- ถ้าลบ: ตัวไหนลบได้ ตัวไหนต้องเก็บ (พร้อมเหตุผล) ----
    const params = { ipsec_profile: fullName };
    const keeps = [];
    if (tsName) {
      if (otherTsUsers.length) keeps.push({ name: tsName, reason: `is shared with ${list(otherTsUsers)}` });
      else params.transform_set = tsName;
    }
    const ikeRemoved = Boolean(ikeProfName) && otherIkeUsers.length === 0;
    if (ikeProfName) {
      if (!ikeRemoved) keeps.push({ name: ikeProfName, reason: `is shared with ${list(otherIkeUsers)}` });
      else params.ikev2_profile = ikeProfName;
    }
    if (keyringName && ikeRemoved) {
      const ownsWhole = otherKeyringUsers.length === 0 && peers.length <= 1 && (peers.length === 0 || ownPeer);
      if (ownsWhole) {
        params.keyring = keyringName;
        params.remove_keyring = true;
      } else if (ownPeer) {
        params.keyring = keyringName;
        params.keyring_peer = ownPeer.name;
        keeps.push({ name: keyringName, reason: "Still used by other peers or IKEv2 profiles (deleting only peer of this Profile)" });
      } else {
        keeps.push({ name: keyringName, reason: "Cannot find peer of this Profile in keyring, skipping deletion" });
      }
    } else if (keyringName) {
      keeps.push({ name: keyringName, reason: "IKEv2 profile using this keyring still exists" });
    }
    // Cisco IKEv2 policy/proposal เป็น global selection ไม่ได้ link กับ IKEv2/IPsec profile
    // จึงจัดการจากสองตารางเฉพาะของมันเท่านั้น ห้ามลบตาม Security Profile ไม่ว่าชื่อจะตรง pattern หรือไม่
    if (policy) keeps.push({ name: policy.name, reason: "Global IKEv2 policy, manage from IKEv2 Policy table" });

    return {
      vendor: "cisco",
      objects: {
        ipsecProfile: fullName,
        transformSet: tsName,
        ikev2Profile: ikeProfName,
        keyring: keyringName,
        keyringPeer: ownPeer?.name || null,
        ikev2Policy: policy?.name || null,
        ikev2Proposal: proposalName || null,
      },
      peerIps,
      pskType,
      raw,
      sections,
      removal: { command: "remove_security_profile_objects", params, keeps },
    };
  };
}

// =====================================================================================
// Juniper
// =====================================================================================

export function resolveJuniperProfileObjects(security) {
  const ike = security?.ike || {};
  const ipsec = security?.ipsec || {};
  const gateways = ensureArray(ike.gateway);
  const ikePolicies = ensureArray(ike.policy);
  const ikeProposals = ensureArray(ike.proposal);
  const vpns = ensureArray(ipsec.vpn);
  const ipsecPolicies = ensureArray(ipsec.policy);
  const ipsecProposals = ensureArray(ipsec.proposal);

  const byName = (items) => Object.fromEntries(items.filter((i) => i?.name).map((i) => [i.name, i]));
  const ikePolicyByName = byName(ikePolicies);
  const ikeProposalByName = byName(ikeProposals);
  const ipsecPolicyByName = byName(ipsecPolicies);
  const ipsecProposalByName = byName(ipsecProposals);

  return function resolve(gateway) {
    const gatewayName = gateway?.name || "";
    const base = gatewayName.replace(/-GATEWAY$/, "") || gatewayName;
    const addresses = ensureArray(gateway?.address);

    const ikePolicyName = gateway?.["ike-policy"] || null;
    const ikePolicy = ikePolicyName ? ikePolicyByName[ikePolicyName] : null;
    const ikeProposalNames = ensureArray(ikePolicy?.proposals);
    const ikeProposalName = ikeProposalNames.length === 1 && !ikePolicy?.["proposal-set"] ? ikeProposalNames[0] : null;
    const ikeProposal = ikeProposalName ? ikeProposalByName[ikeProposalName] : null;

    // ipsec policy ของ profile นี้ = ตัวที่ vpn ซึ่งอ้าง gateway นี้ใช้อยู่ (gateway ตัวเดียวไม่มี link ไป ipsec policy)
    // ไม่มี vpn เลย (ยังไม่ได้สร้าง tunnel) ค่อยลองชื่อตามแบบแผนของระบบ
    const ownVpns = vpns.filter((vpn) => vpn?.ike?.gateway === gatewayName);
    const linkedPolicyNames = [...new Set(ownVpns.map((vpn) => vpn?.ike?.["ipsec-policy"]).filter(Boolean))];
    const ipsecPolicyName = linkedPolicyNames.length === 1
      ? linkedPolicyNames[0]
      : linkedPolicyNames.length === 0 && ipsecPolicyByName[`${base}-IPSEC-POLICY`] ? `${base}-IPSEC-POLICY` : null;
    const ipsecPolicy = ipsecPolicyName ? ipsecPolicyByName[ipsecPolicyName] : null;
    const ipsecProposalNames = ensureArray(ipsecPolicy?.proposals);
    const ipsecProposalName = ipsecProposalNames.length === 1 && !ipsecPolicy?.["proposal-set"] ? ipsecProposalNames[0] : null;
    const ipsecProposal = ipsecProposalName ? ipsecProposalByName[ipsecProposalName] : null;

    // ---- ใครใช้ร่วม ----
    const otherGatewaysOnPolicy = ikePolicyName ? gateways.filter((g) => g?.name !== gatewayName && g?.["ike-policy"] === ikePolicyName).map((g) => g.name) : [];
    const otherPoliciesOnIkeProposal = ikeProposalName
      ? ikePolicies.filter((p) => p?.name !== ikePolicyName && ensureArray(p?.proposals).includes(ikeProposalName)).map((p) => p.name) : [];
    const otherVpnsOnIpsecPolicy = ipsecPolicyName
      ? vpns.filter((vpn) => vpn?.ike?.gateway !== gatewayName && vpn?.ike?.["ipsec-policy"] === ipsecPolicyName).map((vpn) => vpn.name) : [];
    const otherPoliciesOnIpsecProposal = ipsecProposalName
      ? ipsecPolicies.filter((p) => p?.name !== ipsecPolicyName && ensureArray(p?.proposals).includes(ipsecProposalName)).map((p) => p.name) : [];

    const raw = {
      ikev2Encryption: ikeProposal?.["encryption-algorithm"] ? [ikeProposal["encryption-algorithm"]] : [],
      ikev2Integrity: ikeProposal?.["authentication-algorithm"] ? [ikeProposal["authentication-algorithm"]] : [],
      ikev2Group: ikeProposal?.["dh-group"] ? [ikeProposal["dh-group"]] : [],
      ipsecEncryption: ipsecProposal?.["encryption-algorithm"] || null,
      ipsecKeySize: null,
      ipsecIntegrity: ipsecProposal?.["authentication-algorithm"] || null,
      pfsGroup: ipsecPolicy?.["perfect-forward-secrecy"]?.keys || null,
    };

    const sections = {};
    if (gateway?.dynamic) sections.peer = blocked("This Gateway is dynamic (no fixed Peer IP) and cannot be edited via this form");
    else if (addresses.length !== 1) sections.peer = blocked(addresses.length ? `Gateway has ${addresses.length} Peer addresses (${list(addresses)}) and cannot be edited via this form` : "Gateway has no Peer IP");
    else sections.peer = ok();
    sections.wan = ok();

    const pskStructure = ikePolicy?.["pre-shared-key"] || {};
    if (!ikePolicy) sections.psk = blocked(ikePolicyName ? `Cannot find IKE policy ${ikePolicyName} on device` : "Gateway is not bound to an IKE policy");
    else if (otherGatewaysOnPolicy.length) sections.psk = blocked(`IKE policy ${ikePolicyName} is shared with gateway ${list(otherGatewaysOnPolicy)} - editing here will affect those gateways`);
    else if (!("ascii-text" in pskStructure)) sections.psk = blocked("This IKE policy does not use ascii-text PSK (e.g. hexadecimal or certificate)");
    else sections.psk = ok();

    if (!ikePolicy) sections.ikev2 = blocked("No IKE policy, proposal unknown");
    else if (!ikeProposalName) sections.ikev2 = blocked(ikePolicy?.["proposal-set"] ? `IKE policy uses proposal-set (${ikePolicy["proposal-set"]}), not a single proposal` : `IKE policy references ${ikeProposalNames.length} proposals (${list(ikeProposalNames)})`);
    else if (!ikeProposal) sections.ikev2 = blocked(`Cannot find IKE proposal ${ikeProposalName} on device`);
    else if (otherPoliciesOnIkeProposal.length) sections.ikev2 = blocked(`IKE proposal ${ikeProposalName} is shared with policy ${list(otherPoliciesOnIkeProposal)} - editing here will affect those policies`);
    else if (otherGatewaysOnPolicy.length) sections.ikev2 = blocked(`IKE policy ${ikePolicyName} is shared with gateway ${list(otherGatewaysOnPolicy)} - editing here will affect those gateways`);
    else sections.ikev2 = ok();

    if (linkedPolicyNames.length > 1) sections.ipsec = blocked(`VPN of this gateway uses multiple IPsec policies (${list(linkedPolicyNames)})`);
    else if (!ipsecPolicy) sections.ipsec = blocked("No VPN/tunnel bound to this gateway yet, so there is no IPsec policy for this Profile");
    else if (!ipsecProposalName) sections.ipsec = blocked(ipsecPolicy?.["proposal-set"] ? `IPsec policy uses proposal-set (${ipsecPolicy["proposal-set"]}), not a single proposal` : `IPsec policy references ${ipsecProposalNames.length} proposals (${list(ipsecProposalNames)})`);
    else if (!ipsecProposal) sections.ipsec = blocked(`Cannot find IPsec proposal ${ipsecProposalName} on device`);
    else if (otherPoliciesOnIpsecProposal.length) sections.ipsec = blocked(`IPsec proposal ${ipsecProposalName} is shared with policy ${list(otherPoliciesOnIpsecProposal)} - editing here will affect those policies`);
    else if (otherVpnsOnIpsecPolicy.length) sections.ipsec = blocked(`IPsec policy ${ipsecPolicyName} is shared with vpn ${list(otherVpnsOnIpsecPolicy)} - editing here will affect those VPNs`);
    else sections.ipsec = ok();

    if (!ipsecPolicy) sections.pfs = blocked("No IPsec policy for this Profile yet (PFS is on policy)");
    else if (otherVpnsOnIpsecPolicy.length) sections.pfs = blocked(`IPsec policy ${ipsecPolicyName} is shared with vpn ${list(otherVpnsOnIpsecPolicy)} - editing here will affect those VPNs`);
    else sections.pfs = ok();

    // ---- ถ้าลบ ----
    const params = { gateway: gatewayName };
    const keeps = [];
    const policyRemoved = Boolean(ikePolicyName) && otherGatewaysOnPolicy.length === 0;
    if (ikePolicyName) {
      if (policyRemoved) params.ike_policy = ikePolicyName;
      else keeps.push({ name: ikePolicyName, reason: `shared with gateway ${list(otherGatewaysOnPolicy)}` });
    }
    if (ikeProposalName) {
      if (!policyRemoved) keeps.push({ name: ikeProposalName, reason: "Referenced IKE policy is still in use" });
      else if (otherPoliciesOnIkeProposal.length) keeps.push({ name: ikeProposalName, reason: `shared with policy ${list(otherPoliciesOnIkeProposal)}` });
      else params.ike_proposal = ikeProposalName;
    }
    if (ipsecPolicyName) {
      if (otherVpnsOnIpsecPolicy.length) keeps.push({ name: ipsecPolicyName, reason: `shared with vpn ${list(otherVpnsOnIpsecPolicy)}` });
      else params.ipsec_policy = ipsecPolicyName;
    }
    if (ipsecProposalName) {
      if (!params.ipsec_policy) keeps.push({ name: ipsecProposalName, reason: "Referenced IPsec policy is still in use" });
      else if (otherPoliciesOnIpsecProposal.length) keeps.push({ name: ipsecProposalName, reason: `shared with policy ${list(otherPoliciesOnIpsecProposal)}` });
      else params.ipsec_proposal = ipsecProposalName;
    }

    return {
      vendor: "juniper",
      objects: {
        gateway: gatewayName,
        ikePolicy: ikePolicyName,
        ikeProposal: ikeProposalName,
        ipsecPolicy: ipsecPolicyName,
        ipsecProposal: ipsecProposalName,
      },
      peerIps: addresses,
      raw,
      sections,
      removal: { command: "remove_security_profile_objects", params, keeps },
    };
  };
}

// =====================================================================================
// ข้อความสำหรับหน้าเว็บ
// =====================================================================================

const OBJECT_LABELS = {
  ipsecProfile: "IPsec profile", transformSet: "transform-set", ikev2Profile: "IKEv2 profile",
  keyring: "keyring", keyringPeer: "peer in keyring", ikev2Policy: "IKEv2 policy", ikev2Proposal: "IKEv2 proposal",
  gateway: "IKE gateway", ikePolicy: "IKE policy", ikeProposal: "IKE proposal",
  ipsecPolicy: "IPsec policy", ipsecProposal: "IPsec proposal",
};

// object จริงที่ profile นี้ประกอบขึ้น - แสดงให้ผู้ใช้เห็นว่าแก้/ลบอะไรบนอุปกรณ์จริง ๆ
export function describeProfileObjects(real) {
  return Object.entries(real?.objects || {})
    .filter(([, name]) => name)
    .map(([key, name]) => `${OBJECT_LABELS[key]} ${name}`);
}

const REMOVAL_LABELS = {
  ipsec_profile: "IPsec profile", transform_set: "transform-set", ikev2_profile: "IKEv2 profile",
  ikev2_policy: "IKEv2 policy", ikev2_proposal: "IKEv2 proposal",
  gateway: "IKE gateway", ike_policy: "IKE policy", ike_proposal: "IKE proposal",
  ipsec_policy: "IPsec policy", ipsec_proposal: "IPsec proposal",
};

// ข้อความยืนยันการลบ: ตัวที่จะลบ (ชื่อจริง) + ตัวที่จะเก็บไว้พร้อมเหตุผล
export function describeRemoval(real) {
  const params = real?.removal?.params || {};
  const removes = [];
  for (const [key, label] of Object.entries(REMOVAL_LABELS)) {
    if (params[key]) removes.push(`${label} ${params[key]}`);
    if (key === "ikev2_profile" && params.keyring) {
      removes.push(params.remove_keyring ? `keyring ${params.keyring}` : `peer ${params.keyring_peer} in keyring ${params.keyring}`);
    }
  }
  const keeps = (real?.removal?.keeps || []).map((keep) => `${keep.name} (${keep.reason})`);
  let text = `Delete using device real names: ${removes.join(", ")}`;
  if (keeps.length) text += ` · Will not delete: ${keeps.join("; ")}`;
  return text;
}
