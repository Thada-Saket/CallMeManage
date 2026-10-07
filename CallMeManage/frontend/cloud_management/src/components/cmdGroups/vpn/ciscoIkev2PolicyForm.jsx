import DismissibleError from "../../DismissibleError";
import { useState } from "react";
import { runDeviceCommand, validateDeviceCommand } from "../../../api/api_devices";
import IPv4Input from "../../common/IPv4Input";
import { validateIPv4Input } from "../../../utils/ipv4Input";
import { systemPolicyName } from "./ciscoIkev2Objects";

export default function CiscoIkev2PolicyForm({ devId, target, proposalOptions, onClose, onSaved }) {
  const editing = Boolean(target);
  const [name, setName] = useState(target?.name || "");
  const [applied, setApplied] = useState(target?.localIps?.length ? "ip" : "any");
  const [ip, setIp] = useState(target?.localIps?.[0] || "");
  const [proposals, setProposals] = useState(target?.proposals?.length ? target.proposals : [proposalOptions[0] || ""]);
  const [error, setError] = useState(""); const [saving, setSaving] = useState(false);
  const update = (index, value) => setProposals((old) => old.map((item, i) => i === index ? value : item));
  const addProposal = () => setProposals((old) => [
    ...old,
    proposalOptions.find((item) => !old.includes(item)) || proposalOptions[0] || "",
  ]);
  async function submit(event) {
    event.preventDefault();
    if (!name.trim()) return setError("Please enter IKEv2 Policy name");
    const selected = proposals.filter(Boolean);
    if (!selected.length) return setError("Select at least 1 IKEv2 Proposal");
    let localIp;
    if (applied === "ip") {
      const checked = validateIPv4Input(ip, { mode: "address" });
      if (!checked.valid) return setError("Please enter a valid IPv4 Address");
      localIp = checked.value;
    }
    const params = { policy_name: editing ? target.name : systemPolicyName(name.trim()), ikev2_proposals: selected };
    if (editing) params.existing = true;
    if (localIp) params.local_ip = localIp;
    setSaving(true); setError("");
    try { await validateDeviceCommand(devId, "set_ikev2_policy", params); await runDeviceCommand(devId, "set_ikev2_policy", params); onSaved(); }
    catch (err) { setError(err.detail || "Failed to save IKEv2 Policy"); } finally { setSaving(false); }
  }
  return <form className="interface-configuration-form" onSubmit={submit}>
    {editing && <div className="command-output-title">Edit: {target.name}</div>}
    {error && <DismissibleError message={error} onDismiss={() => setError("")} />}
    <div className="interface-configuration-form-field"><label className="data-label">IKEv2 Policy Name</label><input value={name} disabled={editing} onChange={(e) => setName(e.target.value)} required /></div>
    <div className="interface-configuration-form-field"><label className="data-label">Applied on</label><div className="segmented-control">
      <input id="ikev2-policy-applied-any" name="ikev2-policy-applied" type="radio" value="any" checked={applied === "any"} onChange={(e) => setApplied(e.target.value)} /><label htmlFor="ikev2-policy-applied-any">Any</label>
      <input id="ikev2-policy-applied-ip" name="ikev2-policy-applied" type="radio" value="ip" checked={applied === "ip"} onChange={(e) => setApplied(e.target.value)} /><label htmlFor="ikev2-policy-applied-ip">IP</label>
    </div></div>
    {applied === "ip" && <div className="interface-configuration-form-field"><label className="data-label" htmlFor="ikev2-policy-address">IPv4 Address</label><IPv4Input id="ikev2-policy-address" mode="address" label="IPv4 Address" value={ip} onChange={setIp} required /></div>}
    {proposals.map((value, index) => <div key={index} className="interface-configuration-form-field-third"><label className="data-label" htmlFor={`ikev2-policy-proposal-${index}`}>IKEv2 Proposal {index + 1}</label><select id={`ikev2-policy-proposal-${index}`} value={value} onChange={(e) => update(index, e.target.value)}>{proposalOptions.map((option) => <option key={option} value={option}>{option}</option>)}</select>{index === 0 ? <button type="button" className="mini-btn btn-ghost" onClick={addProposal} disabled={proposals.length >= proposalOptions.length} aria-label="Add IKEv2 Proposal">+</button> : <button type="button" className="mini-btn btn-ghost" onClick={() => setProposals((old) => old.filter((_, i) => i !== index))} aria-label={`Remove IKEv2 Proposal ${index + 1}`}>−</button>}</div>)}
    <div className="interface-form-btn-container"><button type="submit" className="btn btn-primary" disabled={saving || !proposalOptions.length}>{saving ? "Applying..." : "Apply"}</button><button type="button" className="btn btn-ghost" onClick={onClose} disabled={saving}>Cancel</button></div>
  </form>;
}
