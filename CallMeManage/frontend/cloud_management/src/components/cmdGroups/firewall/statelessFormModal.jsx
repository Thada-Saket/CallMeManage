import DismissibleError from "../../DismissibleError";
import { useState } from "react";
import { runDeviceCommand, validateDeviceCommand } from "../../../api/api_devices";
import IPv4Input from "../../common/IPv4Input";
import { validateIPv4Input } from "../../../utils/ipv4Input";
import { splitValidatedCidr, wildcardToPrefix, aclAddressToCidr } from "../../../utils/aclPrefix";
import { MAX_ACL_SEQUENCE } from "./aclReferenceCheck";

// ตรงกับ _ACL_NAMED_PROTOCOLS ใน cisco_iosxe.py (Literal ที่ set_acl_rule รับ)
const PROTOCOLS_CISCO = ["ip", "tcp", "udp", "icmp", "ahp", "eigrp", "esp", "gre", "igmp", "ipinip", "nos", "ospf", "pcp", "pim"];

// Junos's ชื่อ protocol ที่รองรับ
const PROTOCOLS_JUNIPER = ["tcp", "udp", "icmp", "icmp6", "ospf", "pim", "igmp", "gre", "esp", "ah", "ipip", "sctp", "vrrp", "rsvp", "egp"];
const PORT_PROTOCOLS = new Set(["tcp", "udp"]);

let clientSeq = 0;
export function nextClientId() {
  return `rule-${Date.now()}-${++clientSeq}`;
}

export function createDefaultCiscoRule(sequence = "10") {
  return {
    clientId: nextClientId(),
    sequence: String(sequence),
    action: "permit",
    protocol: "ip",
    sourceMode: "any",
    sourceCidr: "",
    sourcePort: "",
    destinationMode: "any",
    destinationCidr: "",
    destinationPort: "",
    established: false,
    log: false,
    remark: "",
  };
}

export function createDefaultJuniperRule(termName = "TERM1") {
  return {
    clientId: nextClientId(),
    termName: String(termName),
    action: "permit",
    protocol: "",
    sourceMode: "any",
    sourceCidr: "",
    sourcePort: "",
    destinationMode: "any",
    destinationCidr: "",
    destinationPort: "",
    log: false,
  };
}

function resolveCidrInput(cidrVal, ipVal, wildcardVal, fieldLabel) {
  const raw = (cidrVal !== undefined && cidrVal !== null ? cidrVal : ipVal) || "";
  const trimmed = String(raw).trim();
  if (!trimmed) {
    return { valid: false, error: `Please enter valid ${fieldLabel}` };
  }
  if (trimmed.includes("/")) {
    const check = splitValidatedCidr(trimmed);
    if (!check.valid) return { valid: false, error: check.error || `Please enter valid ${fieldLabel}` };
    return { valid: true, address: check.address, prefix: check.prefix };
  }
  // Fallback สำหรับ legacy caller ที่ส่งแยก IP + Wildcard
  if (wildcardVal !== undefined && wildcardVal !== null) {
    const ipCheck = validateIPv4Input(trimmed, { mode: "address", required: true });
    if (!ipCheck.valid) return { valid: false, error: ipCheck.error || `Please enter valid ${fieldLabel}` };
    const wcTrimmed = String(wildcardVal).trim();
    if (!wcTrimmed || wcTrimmed === "0.0.0.0") {
      return { valid: true, address: ipCheck.value, prefix: 32 };
    }
    const wp = wildcardToPrefix(wcTrimmed);
    if (!wp.representable) {
      return { valid: false, error: `Invalid wildcard or non-contiguous wildcard` };
    }
    return { valid: true, address: ipCheck.value, prefix: wp.prefix };
  }
  const check = splitValidatedCidr(trimmed);
  if (!check.valid) return { valid: false, error: check.error || `Please enter valid ${fieldLabel}` };
  return { valid: true, address: check.address, prefix: check.prefix };
}

export function buildParamsCisco(values) {
  const name = values.name?.trim();
  if (!name) return { error: "Please enter ACL name" };

  const aclType = values.aclType || "extended";

  // โหมด Multi-rule (มี values.rules เป็น Array)
  if (Array.isArray(values.rules)) {
    if (values.rules.length === 0) {
      return { error: "Must have at least 1 Rule" };
    }
    const seenSeqs = new Set();
    const ruleParams = [];

    for (let index = 0; index < values.rules.length; index++) {
      const r = values.rules[index];
      const seqStr = String(r.sequence ?? "").trim();
      if (!seqStr) {
        return { error: `Rule ${index + 1}: Please enter Sequence` };
      }
      const seq = Number(seqStr);
      if (!Number.isInteger(seq) || seq < 1 || seq > MAX_ACL_SEQUENCE) {
        return { error: `Rule ${index + 1}: Sequence must be an integer 1-${MAX_ACL_SEQUENCE}` };
      }
      if (seenSeqs.has(seq)) {
        return { error: `Rule ${index + 1}: Duplicate sequence (${seq})` };
      }
      seenSeqs.add(seq);

      if (aclType === "standard") {
        const rp = {
          sequence: seq,
          action: r.action || "permit",
        };
        if (r.sourceMode === "specific") {
          const res = resolveCidrInput(r.sourceCidr, r.source, r.sourceWildcard, "Source IPv4/Prefix");
          if (!res.valid) return { error: `Rule ${index + 1}: ${res.error}` };
          rp.source = res.address;
          rp.source_prefix = res.prefix;
        } else {
          rp.source = "any";
        }
        if (r.log) rp.log = true;
        if (r.remark?.trim()) rp.remark = r.remark.trim();
        ruleParams.push(rp);
      } else {
        const rp = {
          sequence: seq,
          action: r.action || "permit",
          protocol: r.protocol || "ip",
        };
        if (r.sourceMode === "specific") {
          const res = resolveCidrInput(r.sourceCidr, r.source, r.sourceWildcard, "Source IPv4/Prefix");
          if (!res.valid) return { error: `Rule ${index + 1}: ${res.error}` };
          rp.source = res.address;
          rp.source_prefix = res.prefix;
        } else {
          rp.source = "any";
        }
        if (r.destinationMode === "specific") {
          const res = resolveCidrInput(r.destinationCidr, r.destination, r.destinationWildcard, "Destination IPv4/Prefix");
          if (!res.valid) return { error: `Rule ${index + 1}: ${res.error}` };
          rp.destination = res.address;
          rp.destination_prefix = res.prefix;
        } else {
          rp.destination = "any";
        }

        const portsAllowed = PORT_PROTOCOLS.has(r.protocol);
        if (portsAllowed) {
          if (r.sourcePort !== "" && r.sourcePort != null) rp.source_port = Number(r.sourcePort);
          if (r.destinationPort !== "" && r.destinationPort != null) rp.destination_port = Number(r.destinationPort);
        }

        if (r.protocol === "tcp" && r.established) rp.established = true;
        if (r.log) rp.log = true;
        if (r.remark?.trim()) rp.remark = r.remark.trim();
        ruleParams.push(rp);
      }
    }

    return {
      params: {
        name,
        acl_type: aclType,
        rules: ruleParams,
      },
    };
  }

  // โหมด Singular (รองรับ legacy caller / unit tests เดิม)
  const sequence = Number(values.sequence);
  if (!Number.isInteger(sequence) || sequence < 1 || sequence > MAX_ACL_SEQUENCE) {
    return { error: `Sequence must be an integer 1-${MAX_ACL_SEQUENCE}` };
  }

  if (aclType === "standard") {
    const params = {
      name,
      sequence,
      action: values.action,
      acl_type: "standard",
    };

    if (values.sourceMode === "specific") {
      const res = resolveCidrInput(values.sourceCidr, values.source, values.sourceWildcard, "Source IPv4/Prefix");
      if (!res.valid) return { error: res.error };
      params.source = res.address;
      params.source_prefix = res.prefix;
    }

    if (values.log) params.log = true;
    if (values.remark?.trim()) params.remark = values.remark.trim();

    return { params };
  }

  // Extended ACL (Singular):
  const params = {
    name,
    sequence,
    action: values.action,
    protocol: values.protocol,
    acl_type: "extended",
  };

  if (values.sourceMode === "specific") {
    const res = resolveCidrInput(values.sourceCidr, values.source, values.sourceWildcard, "Source IPv4/Prefix");
    if (!res.valid) return { error: res.error };
    params.source = res.address;
    params.source_prefix = res.prefix;
  }

  if (values.destinationMode === "specific") {
    const res = resolveCidrInput(values.destinationCidr, values.destination, values.destinationWildcard, "Destination IPv4/Prefix");
    if (!res.valid) return { error: res.error };
    params.destination = res.address;
    params.destination_prefix = res.prefix;
  }

  const portsAllowed = PORT_PROTOCOLS.has(values.protocol);
  if (portsAllowed) {
    if (values.sourcePort?.trim()) params.source_port = Number(values.sourcePort);
    if (values.destinationPort?.trim()) params.destination_port = Number(values.destinationPort);
  }

  if (values.protocol === "tcp" && values.established) params.established = true;
  if (values.log) params.log = true;
  if (values.remark?.trim()) params.remark = values.remark.trim();

  return { params };
}

export function buildParamsJuniper(values) {
  const name = values.name?.trim();
  if (!name) return { error: "Please enter ACL name" };

  const hasExtendedFields = Array.isArray(values.rules)
    ? values.rules.some(
        (r) =>
          r.protocol ||
          (r.destination && r.destination !== "any") ||
          (r.destinationCidr && r.destinationCidr !== "any") ||
          (r.sourcePort !== "" && r.sourcePort != null) ||
          (r.destinationPort !== "" && r.destinationPort != null) ||
          r.established
      )
    : Boolean(
        values.protocol ||
          (values.destination && values.destination !== "any") ||
          (values.destinationCidr && values.destinationCidr !== "any") ||
          (values.sourcePort !== "" && values.sourcePort != null) ||
          (values.destinationPort !== "" && values.destinationPort != null) ||
          values.established
      );

  const mode = values.juniperMode || (hasExtendedFields ? "extended" : "standard");
  const revision = values.revision || undefined;

  // โหมด Multi-rule (มี values.rules เป็น Array)
  if (Array.isArray(values.rules)) {
    if (values.rules.length === 0) {
      return { error: "Must have at least 1 Rule" };
    }
    const seenTerms = new Set();
    const ruleParams = [];

    for (let index = 0; index < values.rules.length; index++) {
      const r = values.rules[index];
      const termName = String(r.termName ?? "").trim();
      if (!termName) {
        return { error: `Rule ${index + 1}: Please enter Term name` };
      }
      if (seenTerms.has(termName)) {
        return { error: `Rule ${index + 1}: Duplicate term name (${termName})` };
      }
      seenTerms.add(termName);

      // Term ที่เป็น unsupported brownfield ให้ส่งระบุตัวตนไว้ backend จะรักษาค่าเดิม
      if (r.isRepresentable === false) {
        ruleParams.push({
          term_name: termName,
          action: r.action || "permit",
          is_unsupported: true,
        });
        continue;
      }

      const rp = {
        term_name: termName,
        action: r.action || "permit",
      };

      if (r.sourceMode === "specific") {
        const source = (r.sourceCidr !== undefined ? r.sourceCidr : r.source)?.trim();
        if (!source || source === "any") return { error: `Rule ${index + 1}: Please enter Source IPv4/Prefix` };
        const check = splitValidatedCidr(source);
        if (!check.valid) return { error: `Rule ${index + 1}: Invalid Source IPv4/Prefix (${check.error})` };
        rp.source = check.value;
      }

      if (mode === "extended") {
        if (r.protocol) {
          rp.protocol = r.protocol;
        }

        if (r.destinationMode === "specific") {
          const destination = (r.destinationCidr !== undefined ? r.destinationCidr : r.destination)?.trim();
          if (!destination || destination === "any") return { error: `Rule ${index + 1}: Please enter Destination IPv4/Prefix` };
          const check = splitValidatedCidr(destination);
          if (!check.valid) return { error: `Rule ${index + 1}: Invalid Destination IPv4/Prefix (${check.error})` };
          rp.destination = check.value;
        }

        const portsAllowed = PORT_PROTOCOLS.has(r.protocol);
        if (portsAllowed) {
          if (r.sourcePort !== "" && r.sourcePort != null) {
            const sp = Number(r.sourcePort);
            if (!Number.isInteger(sp) || sp < 0 || sp > 65535) {
              return { error: `Rule ${index + 1}: Source Port must be a number 0-65535` };
            }
            rp.source_port = sp;
          }
          if (r.destinationPort !== "" && r.destinationPort != null) {
            const dp = Number(r.destinationPort);
            if (!Number.isInteger(dp) || dp < 0 || dp > 65535) {
              return { error: `Rule ${index + 1}: Destination Port must be a number 0-65535` };
            }
            rp.destination_port = dp;
          }
        } else {
          if ((r.sourcePort !== "" && r.sourcePort != null) || (r.destinationPort !== "" && r.destinationPort != null)) {
            return { error: `Rule ${index + 1}: Source/Destination Port only applicable for TCP or UDP` };
          }
        }

        if (r.protocol === "tcp" && r.established) {
          rp.established = true;
        }
      }

      if (r.log) rp.log = true;
      ruleParams.push(rp);
    }

    const params = {
      name,
      mode,
      rules: ruleParams,
    };
    if (revision) {
      params.revision = revision;
    }

    return { params };
  }

  // โหมด Singular (รองรับ legacy caller / unit tests เดิม)
  const termName = values.termName?.trim();
  if (!termName) return { error: "Please enter Term name" };

  const params = { name, term_name: termName, action: values.action };
  if (mode === "extended") {
    if (values.protocol) params.protocol = values.protocol;

    if (values.destinationMode === "specific") {
      const destination = (values.destinationCidr !== undefined ? values.destinationCidr : values.destination)?.trim();
      if (!destination || destination === "any") return { error: "Please enter Destination IPv4/Prefix" };
      const check = splitValidatedCidr(destination);
      if (!check.valid) return { error: `Invalid Destination IPv4/Prefix (${check.error})` };
      params.destination = check.value;
    }

    const portsAllowed = PORT_PROTOCOLS.has(values.protocol);
    if (portsAllowed) {
      if (values.sourcePort?.trim()) {
        const sp = Number(values.sourcePort);
        if (!Number.isInteger(sp) || sp < 0 || sp > 65535) return { error: "Source Port must be a number 0-65535" };
        params.source_port = sp;
      }
      if (values.destinationPort?.trim()) {
        const dp = Number(values.destinationPort);
        if (!Number.isInteger(dp) || dp < 0 || dp > 65535) return { error: "Destination Port must be a number 0-65535" };
        params.destination_port = dp;
      }
    } else if (values.sourcePort?.trim() || values.destinationPort?.trim()) {
      return { error: "Source/Destination Port only applicable for TCP or UDP" };
    }

    if (values.protocol === "tcp" && values.established) {
      params.established = true;
    }
  }

  if (values.sourceMode === "specific") {
    const source = (values.sourceCidr !== undefined ? values.sourceCidr : values.source)?.trim();
    if (!source || source === "any") return { error: "Please enter Source IPv4/Prefix" };
    const check = splitValidatedCidr(source);
    if (!check.valid) return { error: `Invalid Source IPv4/Prefix (${check.error})` };
    params.source = check.value;
  }

  if (values.log) params.log = true;
  if (revision) params.revision = revision;

  return { params };
}

export function parseAddressField(text, cidr) {
  if (cidr !== undefined && cidr !== null) {
    if (!cidr || cidr === "any" || cidr === "-") {
      return { mode: "any", value: "", wildcard: "", cidr: "" };
    }
    const cStr = String(cidr).trim();
    if (cStr.includes("/")) {
      return { mode: "specific", value: cStr.split("/")[0] || "", wildcard: "", cidr: cStr };
    }
    return { mode: "specific", value: cStr, wildcard: "", cidr: `${cStr}/32` };
  }
  if (!text || text === "any" || text === "-") return { mode: "any", value: "", wildcard: "", cidr: "" };
  const parts = text.trim().split(/\s+/);
  if (parts.length === 2) {
    const res = aclAddressToCidr(parts[0], parts[1]);
    return { mode: "specific", value: parts[0], wildcard: parts[1], cidr: res.cidr || "" };
  }
  if (parts[0].includes("/")) {
    return { mode: "specific", value: parts[0].split("/")[0], wildcard: "", cidr: parts[0] };
  }
  return { mode: "specific", value: parts[0] || "", wildcard: "", cidr: `${parts[0]}/32` };
}

export function buildInitialValues(mode, editTarget, isJuniper, existingRules = [], editTargetRules = null) {
  const targetRules = (editTargetRules && editTargetRules.length > 0)
    ? editTargetRules
    : (Array.isArray(editTarget) ? editTarget : (editTarget ? [editTarget] : []));

  if (mode !== "edit" || targetRules.length === 0) {
    const defaultSeq = !isJuniper ? "10" : "";
    const firstRule = isJuniper
      ? createDefaultJuniperRule("TERM1")
      : createDefaultCiscoRule("10");
    return {
      aclType: "standard",
      juniperMode: "standard",
      name: "",
      rules: [firstRule],
      revision: "",
      hasBrownfield: false,
      // Fallbacks สำหรับ compatibility กับ unit tests เดิม
      sequence: defaultSeq,
      termName: isJuniper ? "TERM1" : "",
      action: "permit",
      protocol: isJuniper ? "" : "ip",
      sourceMode: "any",
      sourceCidr: "",
      destinationMode: "any",
      destinationCidr: "",
      sourcePort: "",
      destinationPort: "",
      established: false,
      log: false,
      remark: "",
    };
  }

  const first = targetRules[0];
  const aclType = first.aclType || "extended";
  const name = first.aclName || "";
  const revision = first.filterRevision || first.revision || "";

  // Infer mode for Juniper:
  // If any rule has protocol, destination, port, established, or is unsupported -> extended
  const hasExtendedConfig = targetRules.some((r) => {
    const hasProto = r.protocol && r.protocol !== "-" && r.protocol !== "";
    const hasDst = r.destination && r.destination !== "any" && r.destination !== "-" && r.destination !== "" && !r.destination.startsWith("(");
    const hasDstCidr = r.destinationCidr && r.destinationCidr !== "any" && r.destinationCidr !== "";
    const hasSp = r.sourcePort !== "" && r.sourcePort != null;
    const hasDp = r.destinationPort !== "" && r.destinationPort != null;
    const hasEst = Boolean(r.established);
    const isUnrep = r.isRepresentable === false;
    return hasProto || hasDst || hasDstCidr || hasSp || hasDp || hasEst || isUnrep;
  });
  const juniperMode = hasExtendedConfig ? "extended" : "standard";
  const hasBrownfield = targetRules.some((r) => r.isRepresentable === false || r.filterHasBrownfield);

  const rules = targetRules.map((r, index) => {
    const src = parseAddressField(r.source, r.sourceCidr);
    const dst = parseAddressField(r.destination, r.destinationCidr);
    const isRep = r.isRepresentable !== false;
    return {
      clientId: nextClientId(),
      sequence: r.sequence !== "" && r.sequence != null ? String(r.sequence) : String((index + 1) * 10),
      termName: isJuniper ? String(r.termName || r.sequence || `TERM${index + 1}`) : "",
      action: r.action || (isRep ? "permit" : "Unsupported"),
      protocol: r.protocol && r.protocol !== "-" ? r.protocol : (isJuniper ? "" : "ip"),
      sourceMode: r.sourceMode || src.mode,
      sourceCidr: r.sourceCidr !== undefined && r.sourceCidr !== null ? (r.sourceCidr === "any" ? "" : r.sourceCidr) : src.cidr,
      sourcePort: r.sourcePort !== "" && r.sourcePort != null ? String(r.sourcePort) : "",
      destinationMode: r.destinationMode || dst.mode,
      destinationCidr: r.destinationCidr !== undefined && r.destinationCidr !== null ? (r.destinationCidr === "any" ? "" : r.destinationCidr) : dst.cidr,
      destinationPort: r.destinationPort !== "" && r.destinationPort != null ? String(r.destinationPort) : "",
      established: !!r.established,
      log: !!r.log,
      remark: r.remark || "", // preserve brownfield remark
      isRepresentable: isRep,
      unsupportedReasons: r.unsupportedReasons || [],
    };
  });

  return {
    aclType,
    juniperMode,
    name,
    rules,
    revision,
    hasBrownfield,
    // Fallbacks สำหรับ compatibility กับ unit tests เดิม
    sequence: rules[0]?.sequence || "",
    termName: rules[0]?.termName || "",
    action: rules[0]?.action || "permit",
    protocol: rules[0]?.protocol || (isJuniper ? "" : "ip"),
    sourceMode: rules[0]?.sourceMode || "any",
    sourceCidr: rules[0]?.sourceCidr || "",
    destinationMode: rules[0]?.destinationMode || "any",
    destinationCidr: rules[0]?.destinationCidr || "",
    sourcePort: rules[0]?.sourcePort || "",
    destinationPort: rules[0]?.destinationPort || "",
    established: !!rules[0]?.established,
    log: !!rules[0]?.log,
    remark: rules[0]?.remark || "",
  };
}

export default function StatelessFormModal({
  devId,
  vendor,
  mode = "create",
  editTarget = null,
  editTargetRules = null,
  existingRules = [],
  onClose,
  onSaved,
}) {
  const isJuniper = vendor === "juniper";
  const isEdit = mode === "edit";
  const [values, setValues] = useState(() =>
    buildInitialValues(mode, editTarget, isJuniper, existingRules, editTargetRules)
  );
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  function setTopField(name, value) {
    setValues((prev) => ({ ...prev, [name]: value }));
  }

  function handleAclTypeChange(newType) {
    setValues((prev) => ({
      ...prev,
      aclType: newType,
      rules: prev.rules.map((r) => ({
        ...r,
        protocol: newType === "standard" ? "ip" : r.protocol || "ip",
        destinationMode: newType === "standard" ? "any" : r.destinationMode,
        destinationCidr: newType === "standard" ? "" : r.destinationCidr,
        destinationPort: newType === "standard" ? "" : r.destinationPort,
        sourcePort: newType === "standard" ? "" : r.sourcePort,
        established: newType === "standard" ? false : r.established,
      })),
    }));
  }

  function handleJuniperModeChange(newMode) {
    if (newMode === "standard" && values.juniperMode === "extended") {
      const hasData = values.rules.some(
        (r) => r.isRepresentable !== false && (r.protocol || r.destinationCidr || r.sourcePort || r.destinationPort || r.established)
      );
      if (hasData || values.hasBrownfield) {
        const confirmSwitch = window.confirm(
          "Changing to Standard mode will remove Extended properties. Do you want to continue?"
        );
        if (!confirmSwitch) return;
      }
    }
    setValues((prev) => ({
      ...prev,
      juniperMode: newMode,
      rules: prev.rules.map((r) => {
        if (newMode === "standard" && r.isRepresentable !== false) {
          return {
            ...r,
            protocol: "",
            destinationMode: "any",
            destinationCidr: "",
            destinationPort: "",
            sourcePort: "",
            established: false,
          };
        }
        return r;
      }),
    }));
  }

  function addRule() {
    setValues((prev) => {
      if (isJuniper) {
        const nextTerm = `TERM${prev.rules.length + 1}`;
        return {
          ...prev,
          rules: [...prev.rules, createDefaultJuniperRule(nextTerm)],
        };
      } else {
        const currentSeqs = prev.rules
          .map((r) => Number(r.sequence))
          .filter((s) => Number.isInteger(s) && s > 0);
        const maxSeq = currentSeqs.length > 0 ? Math.max(...currentSeqs) : 0;
        const nextSeq = Math.min(maxSeq + 10, MAX_ACL_SEQUENCE);
        return {
          ...prev,
          rules: [...prev.rules, createDefaultCiscoRule(nextSeq)],
        };
      }
    });
  }

  function removeRuleAt(index) {
    if (index === 0) return; // First rule cannot be deleted
    if (values.rules[index]?.isRepresentable === false) return; // Brownfield rule cannot be deleted
    setValues((prev) => ({
      ...prev,
      rules: prev.rules.filter((_, i) => i !== index),
    }));
  }

  function setRuleField(index, field, value) {
    setValues((prev) => {
      const nextRules = [...prev.rules];
      const updated = { ...nextRules[index], [field]: value };
      if (field === "protocol") {
        if (!PORT_PROTOCOLS.has(value)) {
          updated.sourcePort = "";
          updated.destinationPort = "";
        }
        if (value !== "tcp") {
          updated.established = false;
        }
      }
      nextRules[index] = updated;
      return { ...prev, rules: nextRules };
    });
  }

  const protocolOptions = isJuniper ? PROTOCOLS_JUNIPER : PROTOCOLS_CISCO;

  async function handleSubmit(event) {
    event.preventDefault();
    setError("");

    const result = isJuniper ? buildParamsJuniper(values) : buildParamsCisco(values);
    if (result.error) {
      setError(result.error);
      return;
    }

    // Check duplicate ACL name on create
    if (!isEdit) {
      const trimmedName = values.name.trim().toLowerCase();
      if (isJuniper) {
        const exists = existingRules.some((r) => r.aclName?.trim().toLowerCase() === trimmedName);
        if (exists) {
          setError(`Filter "${values.name}" already exists in the system`);
          return;
        }
      } else {
        const targetType = (values.aclType || "extended").toLowerCase();
        const exists = existingRules.some(
          (r) =>
            r.aclName?.trim().toLowerCase() === trimmedName &&
            (r.aclType || "extended").toLowerCase() === targetType
        );
        if (exists) {
          setError(`ACL "${values.name}" (${values.aclType === "standard" ? "Standard" : "Extended"}) already exists in the system`);
          return;
        }
      }
    }

    setSubmitting(true);
    try {
      if (isEdit) {
        // Edit entire ACL atomically in single RPC
        await validateDeviceCommand(devId, "replace_acl", result.params);
        await runDeviceCommand(devId, "replace_acl", result.params);
      } else {
        // Create new ACL with all rules via create_acl (nc:operation="create")
        await validateDeviceCommand(devId, "create_acl", result.params);
        await runDeviceCommand(devId, "create_acl", result.params);
      }
      onSaved();
    } catch (err) {
      const isDataExists =
        err.deviceErrors?.some((e) => e.tag === "data-exists") ||
        /data-exists|already exists|already configured/i.test(err.detail || err.message || "");
      const isConcurrent =
        err.status === 409 ||
        err.error_code === "ACL_CONCURRENT_MODIFICATION" ||
        /ACL_CONCURRENT_MODIFICATION|already modified|ถูกแก้ไขจากอุปกรณ์หรือผู้ใช้อื่น/i.test(
          typeof err.detail === "string" ? err.detail : err.detail?.message || ""
        );
      if (isDataExists) {
        if (isJuniper) {
          setError(`Filter "${values.name}" already exists in the system`);
        } else {
          setError(`ACL "${values.name}" already exists in the system`);
        }
      } else if (isConcurrent) {
        setError("This Firewall Filter was modified by device or another user after opening the form. Please click Refresh and check new data before editing again.");
      } else if (err.error_code === "ACL_UNSUPPORTED_BROWNFIELD_CHANGE" || /ACL_UNSUPPORTED_BROWNFIELD_CHANGE/i.test(err.detail || "")) {
        setError("Cannot edit or delete Brownfield Terms. Please use CLI to manage them.");
      } else if (err.detail && typeof err.detail === "object" && err.detail.fieldErrors) {
        const fieldMsg = err.detail.fieldErrors.map((fe) => fe.message).join("; ");
        setError(err.detail.message ? `${err.detail.message}: ${fieldMsg}` : fieldMsg);
      } else {
        setError(err.detail || (isEdit ? "Failed to edit ACL" : "Failed to create ACL"));
      }
    } finally {
      setSubmitting(false);
    }
  }

  const hasUnrepresentableRule = values.rules.some((r) => r.isRepresentable === false);

  return (
    <form className="interface-configuration-form" onSubmit={handleSubmit}>
      {isEdit && (
        <div className="command-output-title">
          Edit: {values.name} {!isJuniper ? `(${values.aclType === "standard" ? "Standard" : "Extended"}) ` : `(${values.juniperMode === "standard" ? "Standard" : "Extended"}) `}({values.rules.length} {isJuniper ? "terms" : "rules"})
          {hasUnrepresentableRule && (
            <span
              className="locked-form-indicator"
              title={isJuniper
                ? "Unsupported Brownfield properties are preserved and cannot be changed in this form"
                : "A non-contiguous wildcard cannot be changed through the IP/Prefix form"}
              aria-label="Some existing values cannot be changed"
            >🔒</span>
          )}
        </div>
      )}
      {error && <DismissibleError message={error} onDismiss={() => setError("")} />}

      {!isJuniper ? (
        <div className="interface-configuration-form-field">
          <label className="data-label">
            ACL Type
          </label>
          <div
            className={`segmented-control${isEdit ? " locked-choice" : ""}`}
            title={isEdit ? "ACL type is fixed after creation" : undefined}
          >
            <input
              type="radio"
              id="acl-type-standard"
              name="acl-type"
              value="standard"
              checked={values.aclType === "standard"}
              onChange={(event) => handleAclTypeChange(event.target.value)}
              disabled={isEdit}
            />
            <label htmlFor="acl-type-standard">Standard</label>
            <input
              type="radio"
              id="acl-type-extended"
              name="acl-type"
              value="extended"
              checked={values.aclType === "extended"}
              onChange={(event) => handleAclTypeChange(event.target.value)}
              disabled={isEdit}
            />
            <label htmlFor="acl-type-extended">Extended</label>
          </div>
        </div>
      ) : (
        <div className="interface-configuration-form-field">
          <label className="data-label">Filter Mode (UI)</label>
          <div className="segmented-control">
            <input
              type="radio"
              id="juniper-mode-standard"
              name="juniper-mode"
              value="standard"
              checked={values.juniperMode === "standard"}
              onChange={(event) => handleJuniperModeChange(event.target.value)}
            />
            <label htmlFor="juniper-mode-standard">Standard</label>
            <input
              type="radio"
              id="juniper-mode-extended"
              name="juniper-mode"
              value="extended"
              checked={values.juniperMode === "extended"}
              onChange={(event) => handleJuniperModeChange(event.target.value)}
            />
            <label htmlFor="juniper-mode-extended">Extended</label>
          </div>
        </div>
      )}

      <div className="interface-configuration-form-field">
        <label className="data-label">ACL Name</label>
        <input
          type="text"
          placeholder="BLOCK_GUEST"
          value={values.name}
          onChange={(event) => setTopField("name", event.target.value)}
          disabled={isEdit}
          required
        />
      </div>

      {values.rules.map((rule, index) => {
        const portsAllowed = PORT_PROTOCOLS.has(rule.protocol);
        return (
          <div className="acl-rule-block" key={rule.clientId}>
            <div className="acl-rule-block-header">
              <span className="acl-rule-block-title">
                {isJuniper ? `Term ${index + 1}: ${rule.termName || ""}` : `Rule ${index + 1}`}
                {rule.isRepresentable === false && (
                  <span
                    className="locked-form-indicator"
                    style={{
                      marginLeft: "8px",
                    }}
                    title={rule.unsupportedReasons?.join(", ") || "Unsupported configuration"}
                    aria-label="This Brownfield rule cannot be changed"
                  >
                    🔒
                  </span>
                )}
              </span>
              {index === 0 ? (
                <button
                  type="button"
                  className="mini-btn btn-ghost"
                  onClick={addRule}
                  aria-label={isJuniper ? "Add Term" : "Add ACL Rule"}
                  title={isJuniper ? "Add Term" : "Add ACL Rule"}
                >
                  +
                </button>
              ) : (
                <button
                  type="button"
                  className="mini-btn btn-ghost"
                  onClick={() => removeRuleAt(index)}
                  disabled={rule.isRepresentable === false}
                  aria-label={isJuniper ? `Remove Term ${index + 1}` : `Remove ACL Rule ${index + 1}`}
                  title={rule.isRepresentable === false ? "Cannot remove Brownfield Term" : (isJuniper ? `Remove Term ${index + 1}` : `Remove ACL Rule ${index + 1}`)}
                >
                  −
                </button>
              )}
            </div>

            {isJuniper ? (
              <div className="interface-configuration-form-field">
                <label className="data-label">Term Name</label>
                <input
                  type="text"
                  placeholder="TERM1"
                  value={rule.termName}
                  onChange={(event) => setRuleField(index, "termName", event.target.value)}
                  disabled={rule.isRepresentable === false}
                  required
                />
              </div>
            ) : (
              <div className="interface-configuration-form-field">
                <label className="data-label">Sequence</label>
                <input
                  type="number"
                  min="1"
                  max={MAX_ACL_SEQUENCE}
                  value={rule.sequence}
                  onChange={(event) => setRuleField(index, "sequence", event.target.value)}
                  disabled={rule.isRepresentable === false}
                  required
                />
              </div>
            )}

            <div className="interface-configuration-form-field">
              <label className="data-label">Action</label>
              <select
                value={rule.action}
                onChange={(event) => setRuleField(index, "action", event.target.value)}
                disabled={rule.isRepresentable === false}
              >
                <option value="permit">Permit</option>
                <option value="deny">Deny</option>
                {rule.isRepresentable === false && !["permit", "deny"].includes(rule.action) && (
                  <option value={rule.action}>{rule.action}</option>
                )}
              </select>
            </div>

            {((!isJuniper && values.aclType === "extended") || (isJuniper && values.juniperMode === "extended")) && (
              <div className="interface-configuration-form-field">
                <label className="data-label">
                  Protocol{isJuniper ? " (Optional - empty = all protocols)" : ""}
                </label>
                <select
                  value={rule.protocol}
                  onChange={(event) => setRuleField(index, "protocol", event.target.value)}
                  disabled={rule.isRepresentable === false}
                >
                  {isJuniper && <option value="">-- All Protocols --</option>}
                  {protocolOptions.map((protocol) => (
                    <option key={protocol} value={protocol}>
                      {protocol.toUpperCase()}
                    </option>
                  ))}
                </select>
              </div>
            )}

            <div className="interface-configuration-form-field">
              <label className="data-label">Source</label>
              <div className="segmented-control">
                <input
                  type="radio"
                  id={`src-any-${rule.clientId}`}
                  name={`src-mode-${rule.clientId}`}
                  value="any"
                  checked={rule.sourceMode === "any"}
                  onChange={(event) => setRuleField(index, "sourceMode", event.target.value)}
                  disabled={rule.isRepresentable === false}
                />
                <label htmlFor={`src-any-${rule.clientId}`}>Any</label>
                <input
                  type="radio"
                  id={`src-specific-${rule.clientId}`}
                  name={`src-mode-${rule.clientId}`}
                  value="specific"
                  checked={rule.sourceMode === "specific"}
                  onChange={(event) => setRuleField(index, "sourceMode", event.target.value)}
                  disabled={rule.isRepresentable === false}
                />
                <label htmlFor={`src-specific-${rule.clientId}`}>Specific IP</label>
              </div>
            </div>

            {rule.sourceMode === "specific" && (
              <div className="interface-configuration-form-field">
                <label className="data-label">Source IPv4/Prefix</label>
                <IPv4Input
                  mode="cidr"
                  value={rule.sourceCidr}
                  onChange={(val) => setRuleField(index, "sourceCidr", val)}
                  disabled={rule.isRepresentable === false}
                  required
                  label="Source IPv4/Prefix"
                />
              </div>
            )}

            {portsAllowed && ((!isJuniper && values.aclType === "extended") || (isJuniper && values.juniperMode === "extended")) && (
              <div className="interface-configuration-form-field">
                <label className="data-label">Source Port</label>
                <input
                  type="number"
                  min="0"
                  max="65535"
                  value={rule.sourcePort}
                  onChange={(event) => setRuleField(index, "sourcePort", event.target.value)}
                  disabled={rule.isRepresentable === false}
                />
              </div>
            )}

            {((!isJuniper && values.aclType === "extended") || (isJuniper && values.juniperMode === "extended")) && (
              <>
                <div className="interface-configuration-form-field">
                  <label className="data-label">Destination</label>
                  <div className="segmented-control">
                    <input
                      type="radio"
                      id={`dst-any-${rule.clientId}`}
                      name={`dst-mode-${rule.clientId}`}
                      value="any"
                      checked={rule.destinationMode === "any"}
                      onChange={(event) => setRuleField(index, "destinationMode", event.target.value)}
                      disabled={rule.isRepresentable === false}
                    />
                    <label htmlFor={`dst-any-${rule.clientId}`}>Any</label>
                    <input
                      type="radio"
                      id={`dst-specific-${rule.clientId}`}
                      name={`dst-mode-${rule.clientId}`}
                      value="specific"
                      checked={rule.destinationMode === "specific"}
                      onChange={(event) => setRuleField(index, "destinationMode", event.target.value)}
                      disabled={rule.isRepresentable === false}
                    />
                    <label htmlFor={`dst-specific-${rule.clientId}`}>Specific IP</label>
                  </div>
                </div>

                {rule.destinationMode === "specific" && (
                  <div className="interface-configuration-form-field">
                    <label className="data-label">Destination IPv4/Prefix</label>
                    <IPv4Input
                      mode="cidr"
                      value={rule.destinationCidr}
                      onChange={(val) => setRuleField(index, "destinationCidr", val)}
                      disabled={rule.isRepresentable === false}
                      required
                      label="Destination IPv4/Prefix"
                    />
                  </div>
                )}

                {portsAllowed && (
                  <div className="interface-configuration-form-field">
                    <label className="data-label">Destination Port</label>
                    <input
                      type="number"
                      min="0"
                      max="65535"
                      value={rule.destinationPort}
                      onChange={(event) => setRuleField(index, "destinationPort", event.target.value)}
                      disabled={rule.isRepresentable === false}
                    />
                  </div>
                )}
              </>
            )}

            {((!isJuniper && values.aclType === "extended") || (isJuniper && values.juniperMode === "extended")) && rule.protocol === "tcp" && (
              <div className="interface-configuration-form-field">
                <label className="data-label">Established</label>
                <div className="toggle-switch-container">
                  <input
                    type="checkbox"
                    id={`established-${rule.clientId}`}
                    checked={rule.established}
                    onChange={(event) => setRuleField(index, "established", event.target.checked)}
                    disabled={rule.isRepresentable === false}
                  />
                  <label className="toggleSwitch" htmlFor={`established-${rule.clientId}`}></label>
                </div>
              </div>
            )}

            <div className="interface-configuration-form-field">
              <label className="data-label">Log</label>
              <div className="toggle-switch-container">
                <input
                  type="checkbox"
                  id={`log-${rule.clientId}`}
                  checked={rule.log}
                  onChange={(event) => setRuleField(index, "log", event.target.checked)}
                  disabled={rule.isRepresentable === false}
                />
                <label className="toggleSwitch" htmlFor={`log-${rule.clientId}`}></label>
              </div>
            </div>
          </div>
        );
      })}

      <div className="interface-form-btn-container">
        <button
          type="submit"
          className="btn btn-primary"
          disabled={submitting || (!isJuniper && hasUnrepresentableRule)}
        >
          {submitting ? "Sending..." : isEdit ? "Save" : "OK"}
        </button>
        <button type="button" className="btn btn-ghost" onClick={onClose}>
          Cancel
        </button>
      </div>
    </form>
  );
}
