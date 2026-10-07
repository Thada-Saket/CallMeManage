const array = (value) => value == null ? [] : Array.isArray(value) ? value : [value];
const enumKeys = (value) => value && typeof value === "object" ? Object.keys(value) : [];

export function parseCiscoIkev2Objects(result) {
  const ikev2 = result?.payload?.data?.native?.crypto?.ikev2 || {};
  const policies = array(ikev2.policy).filter((item) => item?.name).map((policy) => ({
    name: policy.name,
    localIps: array(policy?.match?.address?.["local-ip"] || policy?.match?.address?.local).filter(Boolean),
    proposals: array(policy?.proposal).map((item) => item?.proposals).filter(Boolean),
  }));
  const proposalUsers = new Map();
  for (const policy of policies) for (const name of policy.proposals) {
    proposalUsers.set(name, [...(proposalUsers.get(name) || []), policy.name]);
  }
  const proposals = array(ikev2.proposal).filter((item) => item?.name).map((proposal) => ({
    name: proposal.name,
    encryption: enumKeys(proposal.encryption),
    integrity: enumKeys(proposal.integrity).length ? enumKeys(proposal.integrity) : enumKeys(proposal.prf),
    dhGroup: enumKeys(proposal.group),
    usedBy: proposalUsers.get(proposal.name) || [],
  }));

  // Cisco เลือก policy ตัวแรกตามชื่อเมื่อ match เงื่อนไขเดียวกัน ตัวอื่นจึงไม่มีวันถูกใช้
  const groups = new Map();
  for (const policy of policies) {
    const keys = policy.localIps.length ? policy.localIps.map((ip) => `ip:${ip}`) : ["any"];
    for (const key of keys) groups.set(key, [...(groups.get(key) || []), policy]);
  }
  for (const matches of groups.values()) {
    matches.sort((a, b) => a.name.localeCompare(b.name, "en"));
    for (const policy of matches.slice(1)) {
      const first = matches[0].name;
      const label = policy.localIps.length ? `Duplicate IP ${policy.localIps.join(", ")}` : "Duplicate Applied on: Any";
      policy.warning = `${label} — Cisco uses policy ${first} (alphabetically first), so this policy will not be used.`;
    }
  }
  return { proposals, policies };
}

export const systemProposalName = (name) => name.endsWith("-IKEV2-PROP") ? name : `${name}-IKEV2-PROP`;
export const systemPolicyName = (name) => name.endsWith("-IKEV2-POLICY") ? name : `${name}-IKEV2-POLICY`;
