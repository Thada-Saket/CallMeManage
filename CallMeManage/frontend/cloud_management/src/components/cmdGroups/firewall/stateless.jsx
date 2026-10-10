import DismissibleError from "../../DismissibleError";
import { useState, useEffect } from "react";
import { runDeviceCommand } from "../../../api/api_devices";
import getDeviceInformation from "../../../hooks/getDeviceInformation";
import StatelessFormModal from "./statelessFormModal";
import Edit_Result from "../../commandResult/edit_command_result";
import { ruleKey, isLastAclRule, checkAclReferencesCisco } from "./aclReferenceCheck";
import AclInterfaceBindingModal from "./aclInterfaceBindingModal";
import { parseInterfaceAclBindings, aggregateAclBindings } from "./aclInterfaceBindings";
import { Reload_Result } from "../../commandResult/reload_command_result";
import PageTabs from "../../common/PageTabs";

const ACL_TABS = [
  { id: "rules", label: "Access Control List Rules" },
  { id: "apply_interface", label: "Apply Rule to Interface" },
];

// รวมแถวที่ ACL name และ ACL type เดียวกันติดกัน (parseAclRules สร้าง rows โดยวน per ACL อยู่
// แล้ว rule ชื่อเดียวกันเลยติดกันเป็น block เสมอ ไม่ต้อง sort ซ้ำ) - คืน array
// ขนาดเท่า rules: index ที่เป็นแถวแรกของ block ได้ค่าเป็นจำนวนแถวใน block นั้น
// (ใช้เป็น rowSpan), index อื่นในบล็อกเดียวกันได้ null (ไม่ render cell ชื่อซ้ำ)
export function computeAclRowSpans(rules) {
  const spans = new Array(rules.length).fill(null);
  let i = 0;
  while (i < rules.length) {
    let j = i + 1;
    while (
      j < rules.length &&
      rules[j].aclName === rules[i].aclName &&
      rules[j].aclType === rules[i].aclType
    ) {
      j++;
    }
    spans[i] = j - i;
    i = j;
  }
  return spans;
}

import { aclAddressToCidr } from "../../../utils/aclPrefix";
import { rowClickSelection, rowDoubleClick } from "../../../utils/rowDoubleClick";

function ensureArray(value) {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

export function extractAddressInfo(ace, anyKey, hostKey, ipKey, maskKey) {
  if (!ace) return aclAddressToCidr("-", null);
  if (anyKey in ace) return aclAddressToCidr("any", null);
  if (ace[hostKey]) return aclAddressToCidr(ace[hostKey], null);
  const ip = ace[ipKey];
  if (ip) return aclAddressToCidr(ip, ace[maskKey] || null);
  return aclAddressToCidr("-", null);
}

export function extractStdAddressInfo(stdAce) {
  if (!stdAce) return aclAddressToCidr("-", null);
  if ("any" in stdAce) return aclAddressToCidr("any", null);
  if (stdAce["host-address"]) return aclAddressToCidr(stdAce["host-address"], null);
  if (stdAce.host) return aclAddressToCidr(stdAce.host, null);
  const ip = stdAce["ipv4-address-prefix"] || stdAce["ipv4-prefix"] || stdAce["ipv4-address"];
  if (ip) return aclAddressToCidr(ip, stdAce.mask || null);
  return aclAddressToCidr("-", null);
}

export function describeAddress(ace, anyKey, hostKey, ipKey, maskKey) {
  return extractAddressInfo(ace, anyKey, hostKey, ipKey, maskKey).display;
}

export function describeStdAddress(stdAce) {
  return extractStdAddressInfo(stdAce).display;
}

// Junos: firewall/family/inet/filter (หลายชื่อ filter ได้) -> term (หลาย term
// ได้ - ตรงกับที่ set_acl_rule เขียน) ใช้ "term name" แทนเลข sequence ของ Cisco
// (Junos ไม่มี sequence number concept แยก)
export function parseJuniperAclRules(result) {
  if (Array.isArray(result?.filters)) {
    const rows = [];
    for (const filter of result.filters) {
      const aclName = filter.name || "";
      const filterRevision = filter.revision || "";
      const filterHasBrownfield = Boolean(filter.hasBrownfieldConfiguration);
      const filterUnsupportedReasons = filter.unsupportedReasons || [];

      const terms = filter.terms || [];
      if (terms.length === 0) {
        rows.push({
          aclName,
          filterRevision,
          filterHasBrownfield,
          filterUnsupportedReasons,
          isEmptyFilter: true,
          sequence: "(Empty)",
          termName: "",
          remark: "",
          action: "-",
          protocol: "-",
          source: "-",
          sourceAddress: "",
          sourceWildcard: null,
          sourceCidr: "",
          sourceRepresentable: false,
          sourceMode: "any",
          sourcePort: "",
          destination: "-",
          destinationAddress: "",
          destinationWildcard: null,
          destinationCidr: "",
          destinationRepresentable: false,
          destinationMode: "any",
          destinationPort: "",
          established: false,
          log: false,
          isRepresentable: false,
          unsupportedReasons: ["Filter has no terms"],
        });
      }

      for (const term of terms) {
        const isRep = term.isRepresentable !== false;
        rows.push({
          aclName,
          filterRevision,
          filterHasBrownfield,
          filterUnsupportedReasons,
          sequence: term.name || "",
          termName: term.name || "",
          remark: "",
          action: term.action || (isRep ? "permit" : "Unsupported"),
          protocol: term.protocol || "-",
          source: term.source || "any",
          sourceAddress: term.source && term.source !== "any" ? term.source : "",
          sourceWildcard: null,
          sourceCidr: term.source && term.source !== "any" ? term.source : "",
          sourceRepresentable: isRep,
          sourceMode: !term.source || term.source === "any" ? "any" : "specific",
          sourcePort: term.sourcePort !== "" && term.sourcePort != null ? String(term.sourcePort) : "",
          destination: term.destination || "any",
          destinationAddress: term.destination && term.destination !== "any" ? term.destination : "",
          destinationWildcard: null,
          destinationCidr: term.destination && term.destination !== "any" ? term.destination : "",
          destinationRepresentable: isRep,
          destinationMode: !term.destination || term.destination === "any" ? "any" : "specific",
          destinationPort: term.destinationPort !== "" && term.destinationPort != null ? String(term.destinationPort) : "",
          established: Boolean(term.established),
          log: Boolean(term.log),
          isRepresentable: isRep,
          unsupportedReasons: term.unsupportedReasons || [],
        });
      }
    }
    return rows;
  }

  const filters = ensureArray(result?.payload?.data?.configuration?.firewall?.family?.inet?.filter);
  const rows = [];
  for (const filter of filters) {
    const aclName = filter?.name || "";
    const filterUnsupportedReasons = [];
    for (const key of Object.keys(filter || {})) {
      if (key !== "name" && key !== "term" && key !== "@attributes") {
        filterUnsupportedReasons.push(`Filter contains ${key}`);
      }
    }
    const filterHasBrownfield = filterUnsupportedReasons.length > 0;

    const terms = ensureArray(filter?.term);
    if (terms.length === 0) {
      rows.push({
        aclName,
        filterRevision: "",
        filterHasBrownfield,
        filterUnsupportedReasons,
        isEmptyFilter: true,
        sequence: "(Empty)",
        termName: "",
        remark: "",
        action: "-",
        protocol: "-",
        source: "-",
        sourceAddress: "",
        sourceWildcard: null,
        sourceCidr: "",
        sourceRepresentable: false,
        sourceMode: "any",
        sourcePort: "",
        destination: "-",
        destinationAddress: "",
        destinationWildcard: null,
        destinationCidr: "",
        destinationRepresentable: false,
        destinationMode: "any",
        destinationPort: "",
        established: false,
        log: false,
        isRepresentable: false,
        unsupportedReasons: ["Filter has no terms"],
      });
    }

    for (const term of terms) {
      const from = term?.from || {};
      const then = term?.then || {};
      const unsupportedReasons = [];

      let srcAddr = "any";
      if (from["source-address"]) {
        if (Array.isArray(from["source-address"])) {
          unsupportedReasons.push("Multiple source-address values are not supported by this form");
          srcAddr = "(Multiple / Unsupported)";
        } else {
          srcAddr = from["source-address"]?.name || "any";
        }
      }

      let dstAddr = "any";
      if (from["destination-address"]) {
        if (Array.isArray(from["destination-address"])) {
          unsupportedReasons.push("Multiple destination-address values are not supported by this form");
          dstAddr = "(Multiple / Unsupported)";
        } else {
          dstAddr = from["destination-address"]?.name || "any";
        }
      }

      let protocol = "";
      if (from.protocol) {
        if (Array.isArray(from.protocol)) {
          unsupportedReasons.push("Multiple protocol values are not supported by this form");
          protocol = "(Multiple)";
        } else {
          protocol = from.protocol;
        }
      }

      let action = "";
      if ("accept" in then) action = "permit";
      else if ("discard" in then) action = "deny";
      else if ("reject" in then) {
        action = "reject";
        unsupportedReasons.push("Unsupported action: reject");
      } else {
        unsupportedReasons.push("Term has no accept or discard action");
      }

      if ("count" in then) unsupportedReasons.push("Term contains counter");
      if ("policer" in then) unsupportedReasons.push("Term contains policer");

      const isRepresentable = unsupportedReasons.length === 0;

      rows.push({
        aclName,
        filterHasBrownfield: filterHasBrownfield || !isRepresentable,
        filterUnsupportedReasons,
        sequence: term?.name || "",
        termName: term?.name || "",
        remark: "",
        action: action || "Unsupported",
        protocol: protocol || "-",
        source: srcAddr,
        sourceAddress: srcAddr.startsWith("(") || srcAddr === "any" ? "" : srcAddr,
        sourceWildcard: null,
        sourceCidr: srcAddr.startsWith("(") || srcAddr === "any" ? "" : srcAddr,
        sourceRepresentable: isRepresentable,
        sourceMode: srcAddr === "any" ? "any" : "specific",
        sourcePort: from["source-port"] ?? "",
        destination: dstAddr,
        destinationAddress: dstAddr.startsWith("(") || dstAddr === "any" ? "" : dstAddr,
        destinationWildcard: null,
        destinationCidr: dstAddr.startsWith("(") || dstAddr === "any" ? "" : dstAddr,
        destinationRepresentable: isRepresentable,
        destinationMode: dstAddr === "any" ? "any" : "specific",
        destinationPort: from["destination-port"] ?? "",
        established: "tcp-established" in from,
        log: "log" in then,
        isRepresentable,
        unsupportedReasons,
      });
    }
  }
  return rows;
}

// แปลงผล get_acl_information (normalize_generic) เป็นรายการ rule แบน (1 แถว/1
// sequence rule) - โครงสร้างตรงกับที่ set_acl_rule เขียน:
// standard (หลาย ACL name ได้) -> access-list-seq-rule (หลาย sequence ได้) -> permit/deny -> std-ace
// extended (หลาย ACL name ได้) -> access-list-seq-rule (หลาย sequence ได้) -> ace-rule
export function parseAclRules(result) {
  if (result?.vendor === "juniper") {
    try {
      return parseJuniperAclRules(result);
    } catch {
      return null;
    }
  }
  try {
    const aclContainer = result?.payload?.data?.native?.ip?.["access-list"];
    if (!aclContainer) return [];

    const rows = [];

    // Parse Standard ACLs
    const standard = aclContainer.standard;
    if (standard) {
      for (const acl of ensureArray(standard)) {
        const aclName = acl?.name || "";
        for (const seqRule of ensureArray(acl?.["access-list-seq-rule"])) {
          const permit = seqRule?.permit;
          const deny = seqRule?.deny;
          const action = permit ? "permit" : deny ? "deny" : "";
          const stdAce = permit?.["std-ace"] || permit || deny?.["std-ace"] || deny || {};
          const srcInfo = extractStdAddressInfo(stdAce);
          rows.push({
            aclType: "standard",
            aclName,
            sequence: seqRule?.sequence ?? "",
            remark: seqRule?.remark || "",
            action,
            protocol: "-",
            source: srcInfo.display,
            sourceAddress: srcInfo.address,
            sourceWildcard: srcInfo.wildcard,
            sourceCidr: srcInfo.cidr,
            sourceRepresentable: srcInfo.representable,
            sourceMode: srcInfo.mode,
            sourcePort: "",
            destination: "-",
            destinationAddress: "",
            destinationWildcard: null,
            destinationCidr: "",
            destinationRepresentable: true,
            destinationMode: "none",
            destinationPort: "",
            established: false,
            log: "log" in stdAce,
            isRepresentable: srcInfo.representable,
          });
        }
      }
    }

    // Parse Extended ACLs
    const extended = aclContainer.extended;
    if (extended) {
      for (const acl of ensureArray(extended)) {
        const aclName = acl?.name || "";
        for (const seqRule of ensureArray(acl?.["access-list-seq-rule"])) {
          const ace = seqRule?.["ace-rule"] || {};
          const srcInfo = extractAddressInfo(ace, "any", "host-address", "ipv4-address", "mask");
          const dstInfo = extractAddressInfo(ace, "dst-any", "dst-host-address", "dest-ipv4-address", "dest-mask");
          const isRepresentable = srcInfo.representable && dstInfo.representable;
          rows.push({
            aclType: "extended",
            aclName,
            sequence: seqRule?.sequence ?? "",
            remark: seqRule?.remark || "",
            action: ace?.action || "",
            protocol: ace?.protocol ?? "",
            source: srcInfo.display,
            sourceAddress: srcInfo.address,
            sourceWildcard: srcInfo.wildcard,
            sourceCidr: srcInfo.cidr,
            sourceRepresentable: srcInfo.representable,
            sourceMode: srcInfo.mode,
            sourcePort: ace?.["src-eq"] ?? "",
            destination: dstInfo.display,
            destinationAddress: dstInfo.address,
            destinationWildcard: dstInfo.wildcard,
            destinationCidr: dstInfo.cidr,
            destinationRepresentable: dstInfo.representable,
            destinationMode: dstInfo.mode,
            destinationPort: ace?.["dst-eq"] ?? "",
            established: "established" in ace,
            log: "log" in ace,
            isRepresentable,
          });
        }
      }
    }

    return rows;
  } catch {
    return null;
  }
}

export default function Stateless({ devId, vendor }) {
  const { data, loading, error, clearError, refetch } = getDeviceInformation(devId, "get_acl_information");
  const [formMode, setFormMode] = useState(null); // null | "create" | "edit" | "apply_interface"
  const [selectedKey, setSelectedKey] = useState(null);
  const [selectedBindingAcl, setSelectedBindingAcl] = useState(null);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState("");
  const [activeTab, setActiveTab] = useState("rules"); // "rules" | "apply_interface"

  const isJuniper = vendor ? vendor === "juniper" : data?.result?.vendor === "juniper";
  const shouldFetchSwitchport = Boolean(vendor) || Boolean(data);

  const {
    data: switchportData,
    loading: switchportLoading,
    refetch: refetchSwitchport,
  } = getDeviceInformation(
    devId,
    shouldFetchSwitchport ? "get_switchport_information" : null
  );

  function handleRefreshAll() {
    refetch();
    refetchSwitchport();
  }

  function handleSaved() {
    setFormMode(null);
    setSelectedKey(null);
    handleRefreshAll();
  }

  const rules = data?.normalized ? parseAclRules(data.result) : null;
  const allInterfaces = switchportData
    ? parseInterfaceAclBindings(switchportData)
    : [];
  const aggregatedBindings = rules !== null
    ? aggregateAclBindings(rules, allInterfaces)
    : [];

  const selectedRule = rules?.find((rule) => ruleKey(rule) === selectedKey) || null;
  const selectedAclRules = selectedRule
    ? rules.filter((r) =>
        isJuniper
          ? r.aclName === selectedRule.aclName
          : r.aclName === selectedRule.aclName && r.aclType === selectedRule.aclType
      )
    : [];
  const canEditAcl =
    selectedAclRules.length > 0 &&
    selectedAclRules.every((r) => r.isRepresentable !== false);
  const isSelectedLast = selectedRule ? isLastAclRule(rules, selectedRule) : false;

  const [aclRefInfo, setAclRefInfo] = useState({ known: true, inUse: false, reasons: [], revision: null });
  const [aclRefLoading, setAclRefLoading] = useState(false);

  // (BUG-77, ขยายขอบเขต 2026-09) ตรวจสอบการอ้างอิง ACL ทุกครั้งที่เลือกกฎของ Cisco
  // ผ่านคำสั่ง get_acl_reference_information เพียงคำสั่งเดียวใน backend
  // known:false หรือกำลังโหลด (aclRefLoading:true) ต้องปิดปุ่ม Delete แบบ fail-closed
  useEffect(() => {
    if (!selectedRule || isJuniper) {
      setAclRefInfo({ known: true, inUse: false, reasons: [], revision: null });
      setAclRefLoading(false);
      return;
    }
    const currentAclName = selectedRule.aclName;
    const currentAclType = selectedRule.aclType || "extended";
    let cancelled = false;
    setAclRefLoading(true);
    setAclRefInfo({ known: false, inUse: false, reasons: [], revision: null }); // fail-closed ระหว่างรอผล

    checkAclReferencesCisco(devId, currentAclName, currentAclType)
      .then((res) => {
        if (!cancelled) {
          setAclRefInfo(res);
          setAclRefLoading(false);
        }
      })
      .catch((err) => {
        if (!cancelled) {
          setAclRefInfo({
            known: false,
            inUse: false,
            reasons: [err?.detail?.message || err?.detail || "Failed to check ACL usage"],
            revision: null,
          });
          setAclRefLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [devId, selectedRule?.aclName, selectedRule?.aclType, isJuniper]);

  // ปิด Delete แบบ fail-closed เมื่อกำลังโหลด, ตรวจไม่สำเร็จ หรือมีฟีเจอร์ใช้งานอยู่จริง
  const ciscoAclBlockedByZbf = !isJuniper && !!selectedRule && (aclRefLoading || !aclRefInfo.known || aclRefInfo.inUse);

  // Juniper's parseJuniperAclRules เก็บชื่อ term ไว้ใน field "sequence" เดิม
  // (คนละความหมายกับ Cisco's numeric sequence) - remove_acl_rule ของ Juniper
  // รับ term_name (string) แทน sequence (number)
  //
  // (BUG-77) จัดการการลบกฎและตัว ACL ให้สะอาด:
  // - ลบตัวกฎ (ACE/term) ด้วย remove_acl_rule เสมอ
  // - สำหรับ Cisco: Backend ตรวจสอบ references (NAT, Interface, ZBF) และ revision ล่าสุด
  //   ภายใต้ DeviceLock เดียวกันก่อน mutation เสมอ
  //   หากเป็น ACE สุดท้ายของ ACL นั้น Backend จะลบทั้ง ACL container ให้อัตโนมัติในคำสั่งเดียว
  //   Frontend จึงส่งคำขอเพียงครั้งเดียวและไม่ต้องตรวจ 3 API ซ้ำ
  async function handleConfirmDelete(rule) {
    setDeleting(true);
    setDeleteError("");
    try {
      if (isJuniper) {
        if (rule.isEmptyFilter) {
          await runDeviceCommand(devId, "remove_acl", {
            name: rule.aclName,
          });
        } else {
          await runDeviceCommand(devId, "remove_acl_rule", {
            name: rule.aclName,
            term_name: String(rule.sequence || rule.termName),
          });
        }
      } else {
        await runDeviceCommand(devId, "remove_acl_rule", {
          name: rule.aclName,
          sequence: Number(rule.sequence),
          acl_type: rule.aclType || "extended",
          expected_revision: aclRefInfo?.revision || undefined,
        });
      }

      setShowDeleteConfirm(false);
      setSelectedKey(null);
      handleRefreshAll();
    } catch (err) {
      const msg = err?.detail?.message || err?.detail || err?.message || "Failed to delete ACL rule";
      setDeleteError(typeof msg === "string" ? msg : JSON.stringify(msg));
    } finally {
      setDeleting(false);
    }
  }

  if (loading && !data) return <div className="center-loading">Fetching Access List data...</div>;

  // สร้างข้อความเตือนเพิ่มเติมใน Delete confirm dialog
  let deleteExtraWarning = "";
  if (selectedRule) {
    if (isJuniper) {
      const inUseIfaces = (allInterfaces || [])
        .filter((i) => i.inboundAcl === selectedRule.aclName || i.outboundAcl === selectedRule.aclName)
        .map((i) => `${i.interfaceName} (${i.inboundAcl === selectedRule.aclName ? "Inbound" : "Outbound"})`);
      const isInUse = inUseIfaces.length > 0;
      if (selectedRule.isEmptyFilter) {
        if (isInUse) {
          deleteExtraWarning = `This Filter is still bound to Interface (${inUseIfaces.join(", ")}) and cannot be deleted. Please unapply first.`;
        } else {
          deleteExtraWarning = `This Filter has no Terms. Deleting will remove the entire Firewall Filter '${selectedRule.aclName}' from the device.`;
        }
      } else {
        const filterTerms = (rules || []).filter((r) => r.aclName === selectedRule.aclName && !r.isEmptyFilter);
        const isLastTerm = filterTerms.length <= 1;
        if (isLastTerm) {
          if (isInUse) {
            deleteExtraWarning = `This is the last Term, and Filter '${selectedRule.aclName}' is still bound to Interface (${inUseIfaces.join(", ")}). It cannot be deleted. Please unapply first.`;
          } else {
            deleteExtraWarning = `This is the last Term. Deleting will remove the entire Firewall Filter '${selectedRule.aclName}' from the device.`;
          }
        } else {
          deleteExtraWarning = "Other Terms remain in this Filter — only this Term will be deleted, keeping the Filter intact.";
        }
      }
    } else if (!aclRefInfo.known) {
      deleteExtraWarning = `Failed to check usage of ACL "${selectedRule.aclName}" - deletion disabled for safety. Please refresh.`;
    } else if (aclRefInfo.inUse) {
      deleteExtraWarning = `Cannot delete any rules in ACL "${selectedRule.aclName}" because it is used by: ${aclRefInfo.reasons.join(", ")} - please edit through that feature's form instead.`;
    } else if (isSelectedLast) {
      deleteExtraWarning = `This is the last rule of ${selectedRule.aclName} — the system will automatically remove this ACL from the device.`;
    } else {
      deleteExtraWarning = "Other rules remain in this ACL — only this rule will be deleted, keeping the ACL intact.";
    }
  }

  return (
    <div className="command-configuration">
      {error && <DismissibleError message={error} onDismiss={clearError} />}

      {formMode === "create" || formMode === "edit" ? (
        <StatelessFormModal
          devId={devId}
          vendor={isJuniper ? "juniper" : "cisco"}
          mode={formMode}
          editTarget={formMode === "edit" ? selectedRule : null}
          editTargetRules={formMode === "edit" ? selectedAclRules : null}
          existingRules={rules || []}
          onClose={() => setFormMode(null)}
          onSaved={handleSaved}
        />
      ) : formMode === "apply_interface" ? (
        <AclInterfaceBindingModal
          key={`${devId}:${selectedBindingAcl}`}
          devId={devId}
          aclName={selectedBindingAcl}
          allInterfaces={allInterfaces}
          interfacesLoading={switchportLoading}
          onClose={() => setFormMode(null)}
          onSaved={handleSaved}
        />
      ) : rules === null ? (
        data && (
          <pre>{typeof data.result === "string" ? data.result : JSON.stringify(data.result, null, 2)}</pre>
        )
      ) : (
        <>
          <PageTabs
            tabs={ACL_TABS}
            activeId={activeTab}
            onChange={setActiveTab}
          />

          {activeTab === "apply_interface" ? (
            <div role="tabpanel" id="tabpanel-apply_interface" aria-labelledby="tab-apply_interface">
              <div className="acl-binding-section">
                <h3 className="cfg-header">Access Control List Interface Bindings</h3>
                <div className="command-output-title acl-binding-header">
                  <div>
                    <button
                      type="button"
                      className="btn btn-primary"
                      disabled={!selectedBindingAcl}
                      onClick={() => setFormMode("apply_interface")}
                    >
                      Edit Interface Rules
                    </button>
                  </div>
                  <Reload_Result
                    loading={loading || switchportLoading}
                    onRefresh={handleRefreshAll}
                  />
                </div>

                {aggregatedBindings.length === 0 ? (
                  <div className="config-placeholder">No Access List bindings to Interfaces</div>
                ) : (
                  <table className="acl-data-table acl-binding-table">
                    <thead>
                      <tr>
                        <th>ACL Name</th>
                        <th>Direction</th>
                        <th>Interfaces</th>
                      </tr>
                    </thead>
                    <tbody>
                      {aggregatedBindings.map((item) => {
                        const isSelected = selectedBindingAcl === item.aclName;
                        return (
                          <tr
                            key={item.aclName}
                            className={`row-clickable ${isSelected ? "row-selected" : ""}`}
                            onClick={(event) =>
                              setSelectedBindingAcl(rowClickSelection(event, item.aclName, selectedBindingAcl))
                            }
                            onDoubleClick={rowDoubleClick(!!selectedBindingAcl, () => setFormMode("apply_interface"))}
                          >
                            <td className="acl-name-cell">
                              {item.aclName}
                              {item.isBrownfieldOnly && (
                                <span
                                  className="field-hint"
                                  style={{ marginLeft: "8px" }}
                                  title="This ACL has no rules in the table above, but is bound to an Interface"
                                >
                                  (Brownfield)
                                </span>
                              )}
                            </td>
                            <td className="acl-binding-direction-cell">
                              <div className="binding-subrow binding-subrow-in">Inbound</div>
                              <div className="binding-subrow binding-subrow-out">Outbound</div>
                            </td>
                            <td className="acl-binding-interfaces-cell">
                              <div className="binding-subrow binding-subrow-in">
                                {item.inboundInterfaces.length > 0
                                  ? item.inboundInterfaces.join(", ")
                                  : "—"}
                              </div>
                              <div className="binding-subrow binding-subrow-out">
                                {item.outboundInterfaces.length > 0
                                  ? item.outboundInterfaces.join(", ")
                                  : "—"}
                              </div>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                )}
              </div>
            </div>
          ) : (
            <div role="tabpanel" id="tabpanel-rules" aria-labelledby="tab-rules">
              <h3 className="cfg-header">Access Control Lists</h3>
              <div className="command-output-title">
                <Edit_Result
                  featureName="ACL"
                  selectedLabel={
                    selectedRule
                      ? `${isJuniper ? "Filter" : selectedRule.aclType === "standard" ? "Standard ACL" : "Extended ACL"} ${selectedRule.aclName} (${selectedAclRules.length} ${isJuniper ? "terms" : "rules"})`
                      : ""
                  }
                  extraWarning={deleteExtraWarning}
                  canEdit={canEditAcl}
                  canDelete={!!selectedKey && !ciscoAclBlockedByZbf}
                  showDeleteConfirm={showDeleteConfirm}
                  deleting={deleting}
                  deleteError={deleteError} onDismissDeleteError={() => setDeleteError("")}
                  onNew={() => setFormMode("create")}
                  onEditClick={() => setFormMode("edit")}
                  onOpenDeleteConfirm={() => setShowDeleteConfirm(true)}
                  onCancelDelete={() => setShowDeleteConfirm(false)}
                  onConfirmDelete={() => handleConfirmDelete(selectedRule)}
                  refreshing={loading || switchportLoading}
                  onRefresh={handleRefreshAll}
                />
              </div>

              {selectedAclRules.some((r) => r.isRepresentable === false || (isJuniper && r.filterHasBrownfield)) && (
                <div
                  style={{
                    background: "var(--warning-dim)",
                    color: "var(--warning)",
                    border: "1px solid var(--warning)",
                    borderRadius: "4px",
                    padding: "8px 12px",
                    marginBottom: "12px",
                    fontSize: "13px",
                  }}
                >
                  {!isJuniper
                    ? "This ACL contains rules with non-contiguous wildcards that cannot be converted to Prefixes without changing their meaning, and cannot be edited via this form, but can still be deleted."
                    : "This Filter has configurations from the device not yet supported by this form. The system will preserve existing values and only allow editing supported Terms."}
                </div>
              )}

              {rules.length === 0 ? (
                <div className="config-placeholder">No Access Lists configured</div>
              ) : (
                <table className="acl-data-table">
                  <thead>
                    <tr>
                      <th>ACL Name</th>
                      {!isJuniper && <th>Type</th>}
                      <th>{isJuniper ? "Term" : "Seq"}</th>
                      <th>Action</th>
                      <th>Protocol</th>
                      <th>Source</th>
                      <th>S.Port</th>
                      <th>Destination</th>
                      <th>D.Port</th>
                      <th>Established</th>
                      <th>Log</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(() => {
                      const nameRowSpans = computeAclRowSpans(rules);
                      return rules.map((rule, index) => {
                        const key = ruleKey(rule);
                        const nameRowSpan = nameRowSpans[index];
                        return (
                          <tr
                            key={`${key}-${index}`}
                            className={`row-clickable ${key === selectedKey ? "row-selected" : ""}`}
                            onClick={(event) => setSelectedKey(rowClickSelection(event, key, selectedKey))}
                            onDoubleClick={rowDoubleClick(canEditAcl, () => setFormMode("edit"))}
                          >
                            {nameRowSpan !== null && (
                              <td className="acl-name-cell" rowSpan={nameRowSpan}>
                                {rule.filterHasBrownfield && (
                                  <span
                                    title={`This Filter has Brownfield configuration:\n${(rule.filterUnsupportedReasons || []).join("\n") || "Contains unsupported Terms"}`}
                                    style={{ color: "#d97706", cursor: "help", marginRight: "6px" }}
                                    aria-label="Brownfield warning"
                                  >
                                    ⚠️
                                  </span>
                                )}
                                {rule.aclName || "-"}
                              </td>
                            )}
                            {!isJuniper && nameRowSpan !== null && (
                              <td className="acl-type-cell" rowSpan={nameRowSpan}>
                                {rule.aclType === "standard" ? "Standard" : "Extended"}
                              </td>
                            )}
                            <td>
                              {rule.isRepresentable === false && (
                                <span
                                  title={`This Term does not support editing via form:\n${(rule.unsupportedReasons || []).join("\n")}`}
                                  style={{ color: "#d97706", cursor: "help", marginRight: "6px" }}
                                  aria-label="Unsupported term warning"
                                >
                                  ⚠️
                                </span>
                              )}
                              {rule.sequence !== "" ? rule.sequence : "-"}
                            </td>
                            <td>{rule.action || "-"}</td>
                            <td>{rule.protocol !== "" ? rule.protocol : "-"}</td>
                            <td>{rule.source}</td>
                            <td>{rule.sourcePort !== "" ? rule.sourcePort : "-"}</td>
                            <td>{rule.destination}</td>
                            <td>{rule.destinationPort !== "" ? rule.destinationPort : "-"}</td>
                            <td>{rule.established ? "Yes" : "No"}</td>
                            <td>{rule.log ? "Yes" : "No"}</td>
                          </tr>
                        );
                      });
                    })()}
                  </tbody>
                </table>
              )}
            </div>
          )}
        </>
      )}

    </div>
  );
}
