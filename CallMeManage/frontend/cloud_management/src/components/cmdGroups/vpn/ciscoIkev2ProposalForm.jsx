import DismissibleError from "../../DismissibleError";
import { useState } from "react";
import { runDeviceCommand, validateDeviceCommand } from "../../../api/api_devices";
import { systemProposalName } from "./ciscoIkev2Objects";

const ENCRYPTIONS = [
  ["aes-cbc-256", "AES-CBC 256-bit"], ["aes-cbc-192", "AES-CBC 192-bit"],
  ["aes-cbc-128", "AES-CBC 128-bit"], ["aes-gcm-256", "AES-GCM 256-bit"], ["aes-gcm-128", "AES-GCM 128-bit"],
];
const INTEGRITIES = [["sha256", "SHA-256"], ["sha384", "SHA-384"], ["sha512", "SHA-512"], ["sha1", "SHA-1"]];
const GROUPS = [["fourteen", "Group 14"], ["fifteen", "Group 15"], ["sixteen", "Group 16"], ["nineteen", "Group 19"], ["twenty", "Group 20"], ["twenty-one", "Group 21"]];

const first = (values, fallback) => values?.[0] || fallback;

export default function CiscoIkev2ProposalForm({ devId, target, onClose, onSaved }) {
  const editing = Boolean(target);
  const current = {
    encryption: first(target?.encryption, "aes-cbc-256"), integrity: first(target?.integrity, "sha256"),
    dh_group: first(target?.dhGroup, "fourteen"),
  };
  const isRecommended = current.encryption === "aes-cbc-256" && current.integrity === "sha256" && current.dh_group === "fourteen";
  const [values, setValues] = useState({ name: target?.name || "", mode: isRecommended ? "recommend" : "specific", ...current });
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);
  const set = (key, value) => setValues((old) => ({ ...old, [key]: value }));

  async function submit(event) {
    event.preventDefault();
    const typed = values.name.trim();
    if (!typed) return setError("Please enter IKEv2 Proposal name");
    const params = {
      proposal_name: editing ? target.name : systemProposalName(typed),
      encryption: values.mode === "recommend" ? "aes-cbc-256" : values.encryption,
      integrity: values.mode === "recommend" ? "sha256" : values.integrity,
      dh_group: values.mode === "recommend" ? "fourteen" : values.dh_group,
    };
    if (editing) params.existing = true;
    setSaving(true); setError("");
    try {
      await validateDeviceCommand(devId, "set_ikev2_proposal", params);
      await runDeviceCommand(devId, "set_ikev2_proposal", params);
      onSaved();
    } catch (err) { setError(err.detail || "Failed to save IKEv2 Proposal"); }
    finally { setSaving(false); }
  }

  return <form className="interface-configuration-form" onSubmit={submit}>
    {editing && <div className="command-output-title">Edit: {target.name}</div>}
    {error && <DismissibleError message={error} onDismiss={() => setError("")} />}
    <div className="interface-configuration-form-field"><label className="data-label">IKEv2 Proposal Name</label>
      <input value={values.name} disabled={editing} onChange={(e) => set("name", e.target.value)} required />
    </div>
    <div className="interface-configuration-form-field"><label className="data-label">IKEv2 Proposal</label><div className="segmented-control">
      <input id="proposal-recommend" type="radio" checked={values.mode === "recommend"} onChange={() => set("mode", "recommend")} /><label htmlFor="proposal-recommend">System Recommend</label>
      <input id="proposal-specific" type="radio" checked={values.mode === "specific"} onChange={() => set("mode", "specific")} /><label htmlFor="proposal-specific">Specific</label>
    </div></div>
    {values.mode === "specific" && <>
      {[ ["encryption", "Encryption", ENCRYPTIONS], ["integrity", values.encryption.startsWith("aes-gcm") ? "PRF" : "Integrity", INTEGRITIES], ["dh_group", "DH Group", GROUPS] ].map(([key, label, options]) =>
        <div className="interface-configuration-form-field" key={key}><label className="data-label">{label}</label><select value={values[key]} onChange={(e) => set(key, e.target.value)}>{options.map(([value, text]) => <option key={value} value={value}>{text}</option>)}</select></div>)}
    </>}
    <div className="interface-form-btn-container"><button type="submit" className="btn btn-primary" disabled={saving}>{saving ? "Applying..." : "Apply"}</button><button type="button" className="btn btn-ghost" onClick={onClose} disabled={saving}>Cancel</button></div>
  </form>;
}
