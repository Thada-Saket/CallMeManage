import DismissibleError from "../../DismissibleError";
import { useState } from "react";
import { runDeviceCommand } from "../../../api/api_devices";
import CiscoIkev2ProposalForm from "./ciscoIkev2ProposalForm";
import CiscoIkev2PolicyForm from "./ciscoIkev2PolicyForm";
import Edit_Result from "../../commandResult/edit_command_result";

const values = (items) => items.length ? items.join(", ") : "-";

export default function CiscoIkev2Tables({ devId, objects, refetch, refreshing, view, setView, section }) {
  const [proposalName, setProposalName] = useState(null);
  const [policyName, setPolicyName] = useState(null);
  const [error, setError] = useState("");
  const [deleteTarget, setDeleteTarget] = useState(null);
  const [deleting, setDeleting] = useState(false);
  const proposal = objects.proposals.find((item) => item.name === proposalName) || null;
  const policy = objects.policies.find((item) => item.name === policyName) || null;
  const saved = () => { setView(null); setProposalName(null); setPolicyName(null); refetch(); };

  async function refresh() {
    setError("");
    setProposalName(null);
    setPolicyName(null);
    setDeleteTarget(null);
    await refetch();
  }

  async function remove() {
    if (!deleteTarget) return;
    setDeleting(true); setError("");
    try { await runDeviceCommand(devId, deleteTarget.command, { name: deleteTarget.name }); setDeleteTarget(null); saved(); }
    catch (err) { setError(err.detail || `Failed to delete ${deleteTarget.label}`); }
    finally { setDeleting(false); }
  }

  if (view?.kind === "proposal") return <CiscoIkev2ProposalForm devId={devId} target={view.target} onClose={() => setView(null)} onSaved={saved} />;
  if (view?.kind === "policy") return <CiscoIkev2PolicyForm devId={devId} target={view.target} proposalOptions={objects.proposals.map((item) => item.name)} onClose={() => setView(null)} onSaved={saved} />;

  const usedReason = proposal?.usedBy.length ? `Cannot delete: policy ${proposal.usedBy.join(", ")} is using this Proposal` : "";
  return <div className="ikev2-object-sections">
    {error && <DismissibleError message={error} onDismiss={() => setError("")} />}
    {(!section || section === "proposal") && (
      <section className="ikev2-object-section"><div className="ikev2-section-heading"><div><h3>IKEv2 Proposal</h3></div></div>
      <div className="command-output-title"><Edit_Result featureName="IKEv2 Proposal" selectedLabel={proposal?.name || ""} extraWarning={usedReason} canEdit={Boolean(proposal)} canDelete={Boolean(proposal) && !usedReason} showDeleteConfirm={deleteTarget?.kind === "proposal"} deleting={deleting} deleteError={error} onDismissDeleteError={() => setError("")} onNew={() => setView({kind: "proposal", target: null})} onEditClick={() => setView({kind: "proposal", target: proposal})} onOpenDeleteConfirm={() => setDeleteTarget({kind: "proposal", command: "remove_ikev2_proposal", name: proposal.name, label: "IKEv2 Proposal"})} onCancelDelete={() => setDeleteTarget(null)} onConfirmDelete={remove} refreshing={refreshing} onRefresh={refresh} /></div>
      {objects.proposals.length ? <table className="data-table"><thead><tr><th>Name</th><th>Encryption</th><th>Integrity / PRF</th><th>DH Group</th></tr></thead><tbody>{objects.proposals.map((item) => <tr key={item.name} className={`row-clickable ${item.name === proposalName ? "row-selected" : ""}`} onClick={() => setProposalName(item.name === proposalName ? null : item.name)}><td>{item.name}</td><td>{values(item.encryption)}</td><td>{values(item.integrity)}</td><td>{values(item.dhGroup)}</td></tr>)}</tbody></table> : <div className="config-placeholder">No IKEv2 Proposal configured</div>}
      </section>
    )}

    {(!section || section === "policy") && (
      <section className="ikev2-object-section"><div className="ikev2-section-heading"><div><h3>IKEv2 Policy</h3></div></div>
      <div className="command-output-title"><Edit_Result featureName="IKEv2 Policy" selectedLabel={policy?.name || ""} canEdit={Boolean(policy)} canDelete={Boolean(policy)} showDeleteConfirm={deleteTarget?.kind === "policy"} deleting={deleting} deleteError={error} onDismissDeleteError={() => setError("")} onNew={() => setView({kind: "policy", target: null})} onEditClick={() => setView({kind: "policy", target: policy})} onOpenDeleteConfirm={() => setDeleteTarget({kind: "policy", command: "remove_ikev2_policy", name: policy.name, label: "IKEv2 Policy"})} onCancelDelete={() => setDeleteTarget(null)} onConfirmDelete={remove} refreshing={refreshing} onRefresh={refresh} /></div>
      {objects.policies.length ? <table className="data-table"><thead><tr><th>Name</th><th>Applied on</th><th>Proposal List</th></tr></thead><tbody>{objects.policies.map((item) => <tr key={item.name} className={`row-clickable ${item.name === policyName ? "row-selected" : ""}`} onClick={() => setPolicyName(item.name === policyName ? null : item.name)}><td>{item.warning && <span title={item.warning} aria-label={item.warning} style={{ color: "#d97706", cursor: "help", marginRight: 6 }}>⚠</span>}{item.name}</td><td>{item.localIps.length ? item.localIps.join(", ") : "Any"}</td><td>{values(item.proposals)}</td></tr>)}</tbody></table> : <div className="config-placeholder">No IKEv2 Policy configured</div>}
      </section>
    )}
  </div>;

}
