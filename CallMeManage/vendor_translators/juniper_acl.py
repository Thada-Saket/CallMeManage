"""Juniper Junos Firewall Filter (Stateless ACL) inspection, normalization,
validation, and atomic term-level patch generator.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from typing import Any
from xml.etree import ElementTree as ET
from tools.safe_xml import safe_fromstring
from xml.sax.saxutils import escape

# Configuration writers in this module are embedded below the Junos YANG
# `<configuration xmlns=".../conf/root">` hierarchy by juniper_junos.py.  The
# old wildcard operational namespace is not a valid child in that hierarchy:
# Junos stops at `<configuration>` and reports `expecting </configuration>`.
# Readers below compare local names and remain compatible with both legacy and
# YANG replies, while every write now uses the same namespace as create_acl().
NS_ROOT = "http://yang.juniper.net/junos-es/conf/root"
NS_FIREWALL = "http://yang.juniper.net/junos-es/conf/firewall"
NS_RPC = "urn:ietf:params:xml:ns:netconf:base:1.0"

# Allowlist of protocols supported by Junos firewall filters and this form
JUNIPER_ACL_PROTOCOLS = {
    "tcp",
    "udp",
    "icmp",
    "icmp6",
    "ospf",
    "pim",
    "igmp",
    "gre",
    "esp",
    "ah",
    "ipip",
    "sctp",
    "vrrp",
    "rsvp",
    "egp",
}

PORT_PROTOCOLS = {"tcp", "udp"}


def _local_name(tag: str) -> str:
    return tag.split("}", 1)[-1]


class JuniperAclValidationError(ValueError):
    """Structured validation error for Juniper ACL / Firewall Filter."""

    def __init__(
        self,
        message: str,
        code: str = "ACL_VALIDATION_ERROR",
        field_errors: list[dict] | None = None,
    ):
        super().__init__(message)
        self.message = message
        self.code = code
        self.field_errors = field_errors or []

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "message": self.message,
            "fieldErrors": self.field_errors,
        }


def canonicalize_juniper_filter(filter_el: ET.Element) -> tuple:
    """Produce a canonical tuple representation of a <filter> element:
    (local_name, text_or_None, tuple(sorted_attributes), tuple(canonical_children))
    ignoring namespace prefixes on tag names, normalizing whitespace in text.
    """
    def _canon_node(el: ET.Element) -> tuple:
        tag = _local_name(el.tag)
        text = (el.text or "").strip()
        attrs = tuple(sorted((_local_name(k), v.strip()) for k, v in el.attrib.items() if not k.startswith("xmlns")))
        children = tuple(_canon_node(c) for c in el if isinstance(c.tag, str) and not c.tag.startswith("{http://www.w3.org/"))
        return (tag, text, attrs, children)

    return _canon_node(filter_el)


def compute_filter_fingerprint(filter_el: ET.Element) -> str:
    """Compute a deterministic hash (revision) of the canonical filter XML element."""
    raw_xml = ET.tostring(filter_el, encoding="unicode")
    normalized = re.sub(r"\s+", " ", raw_xml).strip()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]


calculate_juniper_filter_revision = compute_filter_fingerprint


def validate_ipv4_prefix(val: Any, field_name: str = "IPv4/Prefix", path: str = "") -> str | None:
    """Authoritatively validate an IPv4 address/prefix for Juniper firewall filter."""
    if val is None or str(val).strip() == "" or str(val).strip().lower() == "any":
        return None

    if not isinstance(val, str):
        raise JuniperAclValidationError(
            f"{field_name} must be a string",
            code="ACL_INVALID_IP_PREFIX",
            field_errors=[{"field": field_name, "path": path, "message": f"{field_name} must be a string"}],
        )

    s = val.strip()

    # Reject wildcard masks (e.g. '192.168.1.0 0.0.0.255' or '0.0.0.255')
    if " " in s:
        raise JuniperAclValidationError(
            f"{field_name} does not allow wildcard masks: '{s}'",
            code="ACL_INVALID_IP_PREFIX",
            field_errors=[{"field": field_name, "path": path, "message": "Wildcard mask is not supported; use CIDR prefix"}],
        )

    # Check if CIDR or single IP
    if "/" in s:
        parts = s.split("/")
        if len(parts) != 2:
            raise JuniperAclValidationError(
                f"{field_name} '{s}' is invalid CIDR format",
                code="ACL_INVALID_IP_PREFIX",
                field_errors=[{"field": field_name, "path": path, "message": "Invalid CIDR format"}],
            )
        ip_part, prefix_part = parts[0].strip(), parts[1].strip()
        if not prefix_part.isdigit():
            raise JuniperAclValidationError(
                f"{field_name} prefix '{prefix_part}' must be an integer between 0 and 32",
                code="ACL_INVALID_IP_PREFIX",
                field_errors=[{"field": field_name, "path": path, "message": "Prefix must be an integer between 0 and 32"}],
            )
        prefix_len = int(prefix_part)
        if not 0 <= prefix_len <= 32:
            raise JuniperAclValidationError(
                f"{field_name} prefix '{prefix_len}' must be between 0 and 32",
                code="ACL_INVALID_IP_PREFIX",
                field_errors=[{"field": field_name, "path": path, "message": "Prefix must be between 0 and 32"}],
            )
        try:
            net = ipaddress.IPv4Network(f"{ip_part}/{prefix_len}", strict=False)
        except (ValueError, ipaddress.AddressValueError):
            raise JuniperAclValidationError(
                f"{field_name} '{s}' is not a valid IPv4 prefix",
                code="ACL_INVALID_IP_PREFIX",
                field_errors=[{"field": field_name, "path": path, "message": "Invalid IPv4 prefix"}],
            )
        return str(net)
    else:
        # Bare IP without prefix: validate IPv4 and normalize to /32
        try:
            addr = ipaddress.IPv4Address(s)
        except (ValueError, ipaddress.AddressValueError):
            raise JuniperAclValidationError(
                f"{field_name} '{s}' is not a valid IPv4 address",
                code="ACL_INVALID_IP_PREFIX",
                field_errors=[{"field": field_name, "path": path, "message": "Invalid IPv4 address"}],
            )
        return f"{addr}/32"


def validate_protocol(protocol: Any, path: str = "") -> str | None:
    """Validate protocol against Juniper firewall filter allowlist."""
    if protocol is None or str(protocol).strip() == "":
        return None
    if not isinstance(protocol, str):
        raise JuniperAclValidationError(
            "Protocol must be a string",
            code="ACL_INVALID_PROTOCOL",
            field_errors=[{"field": "protocol", "path": path, "message": "Protocol must be a string"}],
        )
    proto = protocol.strip().lower()
    if proto not in JUNIPER_ACL_PROTOCOLS:
        raise JuniperAclValidationError(
            f"Protocol '{proto}' is not supported by Juniper firewall filter",
            code="ACL_INVALID_PROTOCOL",
            field_errors=[{"field": "protocol", "path": path, "message": f"Unsupported protocol '{proto}'"}],
        )
    return proto


def validate_port(port_val: Any, protocol: str | None, field_name: str, path: str = "") -> int | None:
    """Validate port integer, range (0-65535), and ensure protocol is TCP or UDP."""
    if port_val is None or str(port_val).strip() == "":
        return None

    # CRITICAL: Python bool is a subclass of int, so isinstance(True, int) is True!
    if isinstance(port_val, bool):
        raise JuniperAclValidationError(
            f"{field_name} must be an integer between 0 and 65535, got boolean",
            code="ACL_INVALID_PORT",
            field_errors=[{"field": field_name, "path": path, "message": f"{field_name} cannot be a boolean"}],
        )

    # Reject float or decimal strings like 80.5
    if isinstance(port_val, float) or (isinstance(port_val, str) and "." in port_val):
        raise JuniperAclValidationError(
            f"{field_name} must be an integer between 0 and 65535",
            code="ACL_INVALID_PORT",
            field_errors=[{"field": field_name, "path": path, "message": f"{field_name} must be an integer"}],
        )

    # Check protocol
    if protocol not in PORT_PROTOCOLS:
        raise JuniperAclValidationError(
            f"{field_name} is only allowed with TCP or UDP protocol",
            code="ACL_PORT_WITHOUT_L4",
            field_errors=[{"field": field_name, "path": path, "message": f"{field_name} is only allowed with TCP or UDP protocol"}],
        )

    try:
        val = int(port_val)
    except (ValueError, TypeError):
        raise JuniperAclValidationError(
            f"{field_name} must be an integer between 0 and 65535",
            code="ACL_INVALID_PORT",
            field_errors=[{"field": field_name, "path": path, "message": f"{field_name} must be an integer between 0 and 65535"}],
        )

    if not 0 <= val <= 65535:
        raise JuniperAclValidationError(
            f"{field_name} must be an integer between 0 and 65535",
            code="ACL_INVALID_PORT",
            field_errors=[{"field": field_name, "path": path, "message": f"{field_name} must be an integer between 0 and 65535"}],
        )

    return val


def validate_port_value(port_val: int | str | None, protocol: str | None, field_name: str) -> int | None:
    """Validate port integer and ensure protocol is TCP or UDP (backward-compatibility wrapper)."""
    return validate_port(port_val, protocol, field_name)


def validate_action(action: Any, is_edit: bool = False, path: str = "") -> str:
    """Validate action is 'permit' or 'deny'."""
    if action is None or str(action).strip() == "":
        if is_edit:
            raise JuniperAclValidationError(
                "Action is required",
                code="ACL_INVALID_ACTION",
                field_errors=[{"field": "action", "path": path, "message": "Action is required"}],
            )
        return "permit"

    if not isinstance(action, str):
        raise JuniperAclValidationError(
            "Action must be a string",
            code="ACL_INVALID_ACTION",
            field_errors=[{"field": "action", "path": path, "message": "Action must be a string"}],
        )

    act = action.strip().lower()
    if act not in ("permit", "deny"):
        raise JuniperAclValidationError(
            f"Action must be 'permit' or 'deny', got '{action}'",
            code="ACL_INVALID_ACTION",
            field_errors=[{"field": "action", "path": path, "message": "Action must be 'permit' or 'deny'"}],
        )
    return act


def validate_log(log_val: Any, path: str = "") -> bool:
    """Validate log is a boolean."""
    if log_val is None:
        return False
    if isinstance(log_val, bool):
        return log_val
    if isinstance(log_val, str):
        s = log_val.strip().lower()
        if s in ("true", "1", "yes"):
            return True
        elif s in ("false", "0", "no", ""):
            return False
        raise JuniperAclValidationError(
            f"Log must be a boolean, got '{log_val}'",
            code="ACL_INVALID_LOG",
            field_errors=[{"field": "log", "path": path, "message": "Log must be a boolean"}],
        )
    if isinstance(log_val, int):
        if log_val in (0, 1):
            return bool(log_val)
        raise JuniperAclValidationError(
            f"Log must be a boolean, got {log_val}",
            code="ACL_INVALID_LOG",
            field_errors=[{"field": "log", "path": path, "message": "Log must be a boolean"}],
        )
    raise JuniperAclValidationError(
        f"Log must be a boolean, got {type(log_val).__name__}",
        code="ACL_INVALID_LOG",
        field_errors=[{"field": "log", "path": path, "message": "Log must be a boolean"}],
    )


def validate_established(established_val: Any, protocol: str | None, path: str = "") -> bool:
    """Validate established flag is boolean and only used with TCP."""
    if established_val is None:
        return False
    if isinstance(established_val, bool):
        est = established_val
    elif isinstance(established_val, str):
        s = established_val.strip().lower()
        if s in ("true", "1", "yes"):
            est = True
        elif s in ("false", "0", "no", ""):
            est = False
        else:
            raise JuniperAclValidationError(
                f"Established must be a boolean, got '{established_val}'",
                code="ACL_INVALID_ESTABLISHED",
                field_errors=[{"field": "established", "path": path, "message": "Established must be a boolean"}],
            )
    elif isinstance(established_val, int) and established_val in (0, 1):
        est = bool(established_val)
    else:
        raise JuniperAclValidationError(
            f"Established must be a boolean, got {established_val}",
            code="ACL_INVALID_ESTABLISHED",
            field_errors=[{"field": "established", "path": path, "message": "Established must be a boolean"}],
        )

    if est and protocol != "tcp":
        raise JuniperAclValidationError(
            "Established can only be specified for TCP protocol",
            code="ACL_ESTABLISHED_WITHOUT_TCP",
            field_errors=[{"field": "established", "path": path, "message": "Established is only allowed with TCP protocol"}],
        )
    return est


ALLOWED_RULE_KEYS = {
    "term_name",
    "name",
    "action",
    "protocol",
    "source",
    "destination",
    "source_port",
    "destination_port",
    "log",
    "established",
    "is_unsupported",
    "operation",
    "mode",
}


def validate_juniper_acl_rule(
    rule: dict,
    index: int = 0,
    mode: str = "extended",
    is_edit: bool = False,
) -> dict:
    """Validate a single Juniper ACL rule dict and return normalized rule dict."""
    path_prefix = f"rules[{index}]"

    # Check for unexpected keys
    unexpected_keys = set(rule.keys()) - ALLOWED_RULE_KEYS
    if unexpected_keys:
        bad_key = sorted(unexpected_keys)[0]
        raise JuniperAclValidationError(
            f"Unexpected field '{bad_key}' in rule {index + 1}",
            code="ACL_UNEXPECTED_FIELD",
            field_errors=[{"field": bad_key, "path": f"{path_prefix}.{bad_key}", "message": f"Unexpected field '{bad_key}'"}],
        )

    term_name = rule.get("term_name") or rule.get("name")
    if term_name is None or not str(term_name).strip():
        raise JuniperAclValidationError(
            f"Rule {index + 1}: term_name cannot be empty",
            code="ACL_MISSING_TERM_NAME",
            field_errors=[{"field": "term_name", "path": f"{path_prefix}.term_name", "message": "term_name cannot be empty"}],
        )
    term_name = str(term_name).strip()

    is_unsupported = bool(rule.get("is_unsupported", False))
    if is_unsupported:
        return {
            "term_name": term_name,
            "action": rule.get("action") or "permit",
            "is_unsupported": True,
        }

    action = validate_action(rule.get("action"), is_edit=is_edit, path=f"{path_prefix}.action")

    # In standard mode, extended fields are disregarded or cleared
    if mode == "standard":
        protocol = None
        source = validate_ipv4_prefix(rule.get("source"), "Source IPv4/Prefix", f"{path_prefix}.source")
        destination = None
        source_port = None
        destination_port = None
        established = False
    else:
        protocol = validate_protocol(rule.get("protocol"), path=f"{path_prefix}.protocol")
        source = validate_ipv4_prefix(rule.get("source"), "Source IPv4/Prefix", f"{path_prefix}.source")
        destination = validate_ipv4_prefix(rule.get("destination"), "Destination IPv4/Prefix", f"{path_prefix}.destination")
        source_port = validate_port(rule.get("source_port"), protocol, "Source port", f"{path_prefix}.source_port")
        destination_port = validate_port(rule.get("destination_port"), protocol, "Destination port", f"{path_prefix}.destination_port")
        established = validate_established(rule.get("established"), protocol, f"{path_prefix}.established")

    log = validate_log(rule.get("log"), path=f"{path_prefix}.log")

    return {
        "term_name": term_name,
        "action": action,
        "protocol": protocol,
        "source": source,
        "destination": destination,
        "source_port": source_port,
        "destination_port": destination_port,
        "log": log,
        "established": established,
        "operation": rule.get("operation"),
        "mode": mode,
    }


def validate_juniper_acl_request(
    name: str,
    rules: list[dict],
    mode: str | None = None,
    is_edit: bool = False,
    live_config: str | None = None,
    expected_revision: str | None = None,
) -> dict:
    """Authoritatively validate an entire Juniper ACL request, check duplicates,
    and enforce concurrency and greenfield/brownfield safety when live_config is present.
    """
    if not name or not str(name).strip():
        raise JuniperAclValidationError(
            "ACL name cannot be empty",
            code="ACL_MISSING_NAME",
            field_errors=[{"field": "name", "path": "name", "message": "ACL name cannot be empty"}],
        )
    name = str(name).strip()

    if not rules:
        raise JuniperAclValidationError(
            "rules list cannot be empty",
            code="ACL_EMPTY_RULES",
            field_errors=[{"field": "rules", "path": "rules", "message": "rules list cannot be empty"}],
        )

    eff_mode = mode or "extended"

    seen_terms: set[str] = set()
    normalized_rules: list[dict] = []

    for index, r in enumerate(rules):
        norm_r = validate_juniper_acl_rule(r, index=index, mode=eff_mode, is_edit=is_edit)
        t_name = norm_r["term_name"]
        if t_name in seen_terms:
            raise JuniperAclValidationError(
                f"duplicate term_name '{t_name}' in rules",
                code="ACL_DUPLICATE_TERM",
                field_errors=[{"field": "term_name", "path": f"rules[{index}].term_name", "message": f"duplicate term_name '{t_name}'"}],
            )
        seen_terms.add(t_name)
        normalized_rules.append(norm_r)

    # If live_config is provided, perform authoritative state validation
    if live_config:
        root = safe_fromstring(live_config)
        target_filter_el: ET.Element | None = None
        for el in root.iter():
            if _local_name(el.tag) == "filter":
                for child in el:
                    if _local_name(child.tag) == "name" and (child.text or "").strip() == name:
                        target_filter_el = el
                        break
                if target_filter_el is not None:
                    break

        if not is_edit:
            # Greenfield creation: filter must not already exist!
            if target_filter_el is not None:
                raise ValueError(f"ACL_FILTER_ALREADY_EXISTS: Firewall Filter '{name}' already exists on device")
        else:
            # Edit / Replace: filter must exist!
            if target_filter_el is None:
                raise ValueError(f"ACL_FILTER_NOT_FOUND: Firewall Filter '{name}' not found on device")

            # Check revision / fingerprint for optimistic concurrency
            current_rev = compute_filter_fingerprint(target_filter_el)
            if expected_revision and expected_revision.strip() and expected_revision.strip() != current_rev:
                raise ValueError(
                    f"ACL_CONCURRENT_MODIFICATION: Firewall Filter '{name}' was modified by device or another user. Please refresh and review before editing again"
                )

    return {
        "name": name,
        "mode": eff_mode,
        "rules": normalized_rules,
    }


def inspect_juniper_term(term_el: ET.Element) -> dict:
    """Inspect a single Junos <term> element for representability and extract values."""
    unsupported_reasons: list[str] = []
    term_name = ""
    action = ""
    protocol = ""
    source = "any"
    source_port: int | None = None
    destination = "any"
    destination_port: int | None = None
    log = False
    established = False

    # Check child nodes under <term>
    for child in term_el:
        tag = _local_name(child.tag)
        if tag == "name":
            term_name = (child.text or "").strip()
        elif tag == "from":
            # Inspect <from> container
            from_children = list(child)
            src_addr_elements = [c for c in from_children if _local_name(c.tag) == "source-address"]
            dst_addr_elements = [c for c in from_children if _local_name(c.tag) == "destination-address"]
            proto_elements = [c for c in from_children if _local_name(c.tag) == "protocol"]
            src_port_elements = [c for c in from_children if _local_name(c.tag) == "source-port"]
            dst_port_elements = [c for c in from_children if _local_name(c.tag) == "destination-port"]
            tcp_est_elements = [c for c in from_children if _local_name(c.tag) == "tcp-established"]

            # Check unknown/unsupported match nodes
            known_from_tags = {
                "source-address",
                "destination-address",
                "protocol",
                "source-port",
                "destination-port",
                "tcp-established",
            }
            for fc in from_children:
                fc_tag = _local_name(fc.tag)
                if fc_tag not in known_from_tags:
                    unsupported_reasons.append(f"Unsupported match condition: {fc_tag}")

            # Protocol inspection
            if len(proto_elements) > 1:
                unsupported_reasons.append("Multiple protocol values are not supported by this form")
            elif len(proto_elements) == 1:
                p_text = (proto_elements[0].text or "").strip().lower()
                if p_text in JUNIPER_ACL_PROTOCOLS:
                    protocol = p_text
                else:
                    unsupported_reasons.append(f"Unsupported protocol: {p_text}")

            # Source address inspection
            if len(src_addr_elements) > 1:
                unsupported_reasons.append("Multiple source-address values are not supported by this form")
            elif len(src_addr_elements) == 1:
                sa_el = src_addr_elements[0]
                # Check for except or other unsupported child
                if any(_local_name(c.tag) == "except" for c in sa_el):
                    unsupported_reasons.append("source-address-except is not supported")
                sa_name = None
                for c in sa_el:
                    if _local_name(c.tag) == "name":
                        sa_name = (c.text or "").strip()
                if sa_name:
                    try:
                        ipaddress.IPv4Network(sa_name, strict=False)
                        source = sa_name
                    except ValueError:
                        unsupported_reasons.append(f"Invalid source IPv4/prefix: {sa_name}")
                else:
                    unsupported_reasons.append("source-address missing name")

            # Destination address inspection
            if len(dst_addr_elements) > 1:
                unsupported_reasons.append("Multiple destination-address values are not supported by this form")
            elif len(dst_addr_elements) == 1:
                da_el = dst_addr_elements[0]
                if any(_local_name(c.tag) == "except" for c in da_el):
                    unsupported_reasons.append("destination-address-except is not supported")
                da_name = None
                for c in da_el:
                    if _local_name(c.tag) == "name":
                        da_name = (c.text or "").strip()
                if da_name:
                    try:
                        ipaddress.IPv4Network(da_name, strict=False)
                        destination = da_name
                    except ValueError:
                        unsupported_reasons.append(f"Invalid destination IPv4/prefix: {da_name}")
                else:
                    unsupported_reasons.append("destination-address missing name")

            # Source port inspection
            if len(src_port_elements) > 1:
                unsupported_reasons.append("Multiple source-port values or port range are not supported by this form")
            elif len(src_port_elements) == 1:
                sp_text = (src_port_elements[0].text or "").strip()
                if protocol not in PORT_PROTOCOLS:
                    unsupported_reasons.append("Source port specified without TCP or UDP protocol")
                else:
                    try:
                        val = int(sp_text)
                        if 0 <= val <= 65535:
                            source_port = val
                        else:
                            unsupported_reasons.append(f"Invalid source port: {sp_text}")
                    except ValueError:
                        unsupported_reasons.append(f"Non-integer source port: {sp_text}")

            # Destination port inspection
            if len(dst_port_elements) > 1:
                unsupported_reasons.append("Multiple destination-port values or port range are not supported by this form")
            elif len(dst_port_elements) == 1:
                dp_text = (dst_port_elements[0].text or "").strip()
                if protocol not in PORT_PROTOCOLS:
                    unsupported_reasons.append("Destination port specified without TCP or UDP protocol")
                else:
                    try:
                        val = int(dp_text)
                        if 0 <= val <= 65535:
                            destination_port = val
                        else:
                            unsupported_reasons.append(f"Invalid destination port: {dp_text}")
                    except ValueError:
                        unsupported_reasons.append(f"Non-integer destination port: {dp_text}")

            # TCP established inspection
            if tcp_est_elements:
                if protocol != "tcp":
                    unsupported_reasons.append("tcp-established specified without TCP protocol")
                else:
                    established = True

        elif tag == "then":
            # Inspect <then> container
            then_children = list(child)
            has_accept = any(_local_name(c.tag) == "accept" for c in then_children)
            has_discard = any(_local_name(c.tag) == "discard" for c in then_children)
            has_reject = any(_local_name(c.tag) == "reject" for c in then_children)
            has_next_term = any(_local_name(c.tag) == "next-term" for c in then_children)

            if has_accept and not has_discard and not has_reject and not has_next_term:
                action = "permit"
            elif has_discard and not has_accept and not has_reject and not has_next_term:
                action = "deny"
            elif has_reject:
                unsupported_reasons.append("Unsupported action: reject")
            elif has_next_term:
                unsupported_reasons.append("Term contains next-term action")
            elif not has_accept and not has_discard:
                unsupported_reasons.append("Term has no accept or discard action")
            else:
                unsupported_reasons.append("Term has multiple terminating actions")

            # Check non-terminating actions
            for tc in then_children:
                tc_tag = _local_name(tc.tag)
                if tc_tag == "log":
                    log = True
                elif tc_tag in ("accept", "discard", "reject", "next-term"):
                    pass
                elif tc_tag == "count":
                    unsupported_reasons.append("Term contains counter")
                elif tc_tag == "policer":
                    unsupported_reasons.append("Term contains policer")
                elif tc_tag == "three-color-policer":
                    unsupported_reasons.append("Term contains three-color-policer")
                elif tc_tag == "syslog":
                    unsupported_reasons.append("Term contains syslog")
                elif tc_tag == "sample":
                    unsupported_reasons.append("Term contains sample")
                else:
                    unsupported_reasons.append(f"Unsupported action node: {tc_tag}")
        else:
            unsupported_reasons.append(f"Unsupported term node: {tag}")

    is_representable = len(unsupported_reasons) == 0

    return {
        "name": term_name,
        "termName": term_name,
        "isRepresentable": is_representable,
        "unsupportedReasons": unsupported_reasons,
        "action": action,
        "protocol": protocol,
        "source": source,
        "sourceCidr": source,
        "sourcePort": source_port if source_port is not None else "",
        "destination": destination,
        "destinationCidr": destination,
        "destinationPort": destination_port if destination_port is not None else "",
        "log": log,
        "established": established,
    }


def inspect_juniper_filter(filter_el: ET.Element) -> dict:
    """Inspect a Junos <filter> element for representability, terms, and fingerprint."""
    filter_name = ""
    unsupported_reasons: list[str] = []
    terms: list[dict] = []

    for child in filter_el:
        tag = _local_name(child.tag)
        if tag == "name":
            filter_name = (child.text or "").strip()
        elif tag == "term":
            terms.append(inspect_juniper_term(child))
        elif tag == "interface-specific":
            unsupported_reasons.append("Filter contains interface-specific")
        elif tag == "physical-interface-filter":
            unsupported_reasons.append("Filter contains physical-interface-filter")
        elif tag == "enhanced-mode":
            unsupported_reasons.append("Filter contains enhanced-mode")
        elif tag == "accounting-profile":
            unsupported_reasons.append("Filter contains accounting-profile")
        elif tag == "apply-groups":
            unsupported_reasons.append("Filter contains apply-groups")
        else:
            unsupported_reasons.append(f"Filter contains unsupported node: {tag}")

    revision = compute_filter_fingerprint(filter_el)
    has_brownfield = len(unsupported_reasons) > 0 or any(not t["isRepresentable"] for t in terms)
    is_fully_representable = len(unsupported_reasons) == 0 and all(t["isRepresentable"] for t in terms)

    return {
        "name": filter_name,
        "isFullyRepresentable": is_fully_representable,
        "hasBrownfieldConfiguration": has_brownfield,
        "filterHasBrownfield": has_brownfield,
        "unsupportedReasons": unsupported_reasons,
        "revision": revision,
        "filterRevision": revision,
        "terms": terms,
    }


def normalize_juniper_acl_information(xml_response: str, element_to_json_func=None) -> dict:
    """Parse a Junos get_acl_information NETCONF reply into normalized filters with representability metadata."""
    root = safe_fromstring(xml_response)
    filters: list[dict] = []

    # Find all <filter> elements under configuration/firewall/family/inet/filter
    for el in root.iter():
        if _local_name(el.tag) == "filter":
            # Check parent hierarchy or name
            name_el = el.find("name")
            if name_el is None:
                for child in el:
                    if _local_name(child.tag) == "name":
                        name_el = child
                        break
            if name_el is not None and name_el.text:
                filters.append(inspect_juniper_filter(el))

    payload = element_to_json_func(root) if element_to_json_func else {}
    return {
        "vendor": "juniper",
        "payload": payload,
        "filters": filters,
    }


def build_juniper_term_xml(
    term_name: str | dict,
    action: str | None = None,
    protocol: str | None = None,
    source: str | None = None,
    destination: str | None = None,
    source_port: int | None = None,
    destination_port: int | None = None,
    log: bool = False,
    established: bool = False,
    operation: str | None = None,
    mode: str = "extended",
) -> str:
    """Serialize a single Junos <term> XML block with proper validation."""
    if isinstance(term_name, dict):
        rule = term_name
        return build_juniper_term_xml(
            term_name=rule.get("term_name") or rule.get("name"),
            action=action or rule.get("action", "permit"),
            protocol=protocol or rule.get("protocol"),
            source=source or rule.get("source"),
            destination=destination or rule.get("destination"),
            source_port=source_port if source_port is not None else rule.get("source_port"),
            destination_port=destination_port if destination_port is not None else rule.get("destination_port"),
            log=log or bool(rule.get("log", False)),
            established=established or bool(rule.get("established", False)),
            operation=operation or rule.get("operation"),
            mode=mode or rule.get("mode", "extended"),
        )

    if not term_name or not str(term_name).strip():
        raise JuniperAclValidationError(
            "term_name cannot be empty",
            code="ACL_MISSING_TERM_NAME",
            field_errors=[{"field": "term_name", "path": "term_name", "message": "term_name cannot be empty"}],
        )
    term_name = str(term_name).strip()

    norm_action = validate_action(action, is_edit=False, path="action")

    if mode == "standard":
        proto = None
        src = validate_ipv4_prefix(source, "Source IPv4/Prefix", path="source")
        dst = None
        sp = None
        dp = None
        est = False
    else:
        proto = validate_protocol(protocol, path="protocol")
        src = validate_ipv4_prefix(source, "Source IPv4/Prefix", path="source")
        dst = validate_ipv4_prefix(destination, "Destination IPv4/Prefix", path="destination")
        sp = validate_port(source_port, proto, "Source port", path="source_port")
        dp = validate_port(destination_port, proto, "Destination port", path="destination_port")
        est = validate_established(established, proto, path="established")

    norm_log = validate_log(log, path="log")

    from_parts = []
    if proto:
        from_parts.append(f"<protocol>{escape(proto)}</protocol>")
    if src:
        from_parts.append(f"<source-address><name>{escape(src)}</name></source-address>")
    if dst:
        from_parts.append(f"<destination-address><name>{escape(dst)}</name></destination-address>")
    if sp is not None:
        from_parts.append(f"<source-port>{sp}</source-port>")
    if dp is not None:
        from_parts.append(f"<destination-port>{dp}</destination-port>")
    if est:
        from_parts.append("<tcp-established/>")

    from_xml = f"<from>{''.join(from_parts)}</from>" if from_parts else ""
    action_xml = "<accept/>" if norm_action == "permit" else "<discard/>"
    log_xml = "<log/>" if norm_log else ""
    op_attr = f' xmlns:nc="{NS_RPC}" nc:operation="{operation}"' if operation else ""

    return f"""
        <term{op_attr}>
          <name>{escape(term_name)}</name>
          {from_xml}
          <then>
            {action_xml}
            {log_xml}
          </then>
        </term>"""


def build_juniper_replace_acl_payload(
    name: str,
    rules: list[dict],
    mode: str | None = None,
    revision: str | None = None,
    deleted_terms: list[str] | None = None,
    reference_config: str | None = None,
) -> str:
    """Build atomic NETCONF edit-config payload for replace_acl on Juniper Junos.
    When reference_config is provided, uses Term-level atomic patch preserving
    all unsupported/brownfield terms and filter-level nodes.
    """
    validated = validate_juniper_acl_request(
        name=name,
        rules=rules,
        mode=mode,
        is_edit=True,
        live_config=reference_config,
        expected_revision=revision,
    )
    name = validated["name"]

    # When reference_config is provided, perform term-level atomic patch with Brownfield safety
    if reference_config:
        root = safe_fromstring(reference_config)
        target_filter_el: ET.Element | None = None
        for el in root.iter():
            if _local_name(el.tag) == "filter":
                for child in el:
                    if _local_name(child.tag) == "name" and (child.text or "").strip() == name:
                        target_filter_el = el
                        break
                if target_filter_el is not None:
                    break

        if target_filter_el is None:
            raise ValueError(f"ACL_FILTER_NOT_FOUND: Firewall Filter '{name}' not found on device")

        # Check revision / fingerprint for concurrent modification
        current_rev = compute_filter_fingerprint(target_filter_el)
        if revision and revision.strip() and revision.strip() != current_rev:
            raise ValueError(
                f"ACL_CONCURRENT_MODIFICATION: Firewall Filter '{name}' was modified by device or another user. Please refresh and review before editing again"
            )

        # Inspect current terms on device
        existing_terms: dict[str, dict] = {}
        for child in target_filter_el:
            if _local_name(child.tag) == "term":
                inspected = inspect_juniper_term(child)
                existing_terms[inspected["name"]] = inspected

        # Check if user attempts to modify or delete any unsupported term
        rules_term_names = {str(r.get("term_name") or "").strip() for r in rules}

        # Check modified terms
        for r in rules:
            r_name = str(r.get("term_name") or "").strip()
            if r_name in existing_terms:
                old_term = existing_terms[r_name]
                if not old_term["isRepresentable"]:
                    if r.get("is_unsupported") is True:
                        # Preserved read-only brownfield term
                        continue
                    # Cannot modify unsupported term
                    raise ValueError(
                        f"ACL_UNSUPPORTED_BROWNFIELD_CHANGE: Term '{r_name}' has configurations not supported by the form and cannot be edited or deleted here"
                    )

        # Check deleted terms
        effective_deleted: set[str] = set()
        if deleted_terms:
            effective_deleted.update(deleted_terms)
        for old_name, old_info in existing_terms.items():
            if old_name not in rules_term_names:
                effective_deleted.add(old_name)

        for d_name in effective_deleted:
            if d_name in existing_terms:
                old_info = existing_terms[d_name]
                if not old_info["isRepresentable"]:
                    raise ValueError(
                        f"ACL_UNSUPPORTED_BROWNFIELD_CHANGE: Term '{d_name}' has configurations not supported by the form and cannot be edited or deleted here"
                    )

        # Build term-level patch
        terms_xml_parts: list[str] = []

        # 1. Terms in rules: either 'replace' (if existed) or 'create' (if new)
        for r in rules:
            if r.get("is_unsupported"):
                # Untouched brownfield term: omit from payload so Junos leaves it intact
                continue
            t_name = str(r["term_name"]).strip()
            is_new = t_name not in existing_terms
            op = "create" if is_new else "replace"

            terms_xml_parts.append(
                build_juniper_term_xml(
                    term_name=t_name,
                    action=r.get("action") or "permit",
                    protocol=r.get("protocol") or None,
                    source=r.get("source") or None,
                    destination=r.get("destination") or None,
                    source_port=r.get("source_port"),
                    destination_port=r.get("destination_port"),
                    log=bool(r.get("log", False)),
                    established=bool(r.get("established", False)),
                    operation=op,
                    mode=mode or "extended",
                )
            )

        # 2. Deleted representable terms: 'remove'
        for d_name in sorted(effective_deleted):
            if d_name in existing_terms:
                terms_xml_parts.append(f"""
        <term xmlns:nc="{NS_RPC}" nc:operation="remove">
          <name>{escape(d_name)}</name>
        </term>""")

        terms_xml = "".join(terms_xml_parts)

        # Notice: <filter> has NO nc:operation="replace"!
        # This keeps all filter-level nodes and untouched terms intact!
        return f"""
<firewall xmlns="{NS_FIREWALL}">
  <family>
    <inet>
      <filter>
        <name>{escape(name)}</name>
        {terms_xml}
      </filter>
    </inet>
  </family>
</firewall>"""

    # Standalone / fallback mode (when no reference_config is provided, e.g. in mock tests)
    terms_xml_parts = []
    for r in rules:
        t_name = str(r["term_name"]).strip()
        terms_xml_parts.append(
            build_juniper_term_xml(
                term_name=t_name,
                action=r.get("action") or "permit",
                protocol=r.get("protocol") or None,
                source=r.get("source") or None,
                destination=r.get("destination") or None,
                source_port=r.get("source_port"),
                destination_port=r.get("destination_port"),
                log=bool(r.get("log", False)),
                established=bool(r.get("established", False)),
            )
        )

    terms_xml = "".join(terms_xml_parts)
    return f"""
<firewall xmlns="{NS_FIREWALL}">
  <family>
    <inet>
      <filter xmlns:nc="{NS_RPC}" nc:operation="replace">
        <name>{escape(name)}</name>
        {terms_xml}
      </filter>
    </inet>
  </family>
</firewall>"""


NS_INTERFACES = "http://yang.juniper.net/junos-es/conf/interfaces"


def compute_bindings_fingerprint(interfaces: list[dict]) -> str:
    """Compute a deterministic hash of interface filter bindings."""
    parts = []
    for iface in sorted(interfaces, key=lambda x: x["interfaceName"]):
        parts.append(
            f"{iface['interfaceName']}:in={iface.get('inboundAcl') or ''}:out={iface.get('outboundAcl') or ''}"
        )
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def parse_juniper_interface_bindings(xml_or_root: str | ET.Element) -> dict:
    """Parse Junos running interfaces configuration into interface units and filter bindings."""
    if isinstance(xml_or_root, str):
        if not xml_or_root or not xml_or_root.strip():
            return {"interfaces": [], "bindings": [], "fingerprint": ""}
        root = safe_fromstring(xml_or_root)
    else:
        root = xml_or_root

    interfaces: list[dict] = []
    bindings: list[dict] = []

    # Find <interfaces> element
    for iface_el in root.iter():
        if _local_name(iface_el.tag) != "interface":
            continue

        name_el = iface_el.find("name")
        if name_el is None:
            for child in iface_el:
                if _local_name(child.tag) == "name":
                    name_el = child
                    break
        if name_el is None or not name_el.text:
            continue

        if_type = name_el.text.strip()
        units = [c for c in iface_el if _local_name(c.tag) == "unit"]

        if not units:
            # Interface without unit
            interfaces.append({
                "interfaceName": if_type,
                "interfaceType": if_type,
                "unit": "",
                "inboundAcl": None,
                "outboundAcl": None,
                "isRepresentable": False,
                "unsupportedReasons": ["Interface has no unit"],
            })
            continue

        for unit in units:
            unit_name_el = unit.find("name")
            if unit_name_el is None:
                for child in unit:
                    if _local_name(child.tag) == "name":
                        unit_name_el = child
                        break
            unit_name = (unit_name_el.text or "").strip() if unit_name_el is not None else ""
            display_if = f"{if_type}.{unit_name}" if unit_name else if_type

            is_rep = True
            unsupported_reasons: list[str] = []

            if not unit_name or not unit_name.isdigit():
                is_rep = False
                unsupported_reasons.append(f"Non-integer or invalid unit: '{unit_name}'")

            in_acl = None
            out_acl = None

            # Look for family -> inet -> filter
            for fam in unit:
                if _local_name(fam.tag) == "family":
                    for inet in fam:
                        if _local_name(inet.tag) == "inet":
                            for flt in inet:
                                if _local_name(flt.tag) == "filter":
                                    for fc in flt:
                                        fc_tag = _local_name(fc.tag)
                                        if fc_tag == "input":
                                            val = (fc.text or "").strip()
                                            if not val:
                                                for child in fc:
                                                    if _local_name(child.tag) == "filter-name" and child.text:
                                                        val = child.text.strip()
                                                        break
                                            in_acl = val if val else None
                                        elif fc_tag == "output":
                                            val = (fc.text or "").strip()
                                            if not val:
                                                for child in fc:
                                                    if _local_name(child.tag) == "filter-name" and child.text:
                                                        val = child.text.strip()
                                                        break
                                            out_acl = val if val else None
                                        elif fc_tag in ("input-list", "input-chain"):
                                            is_rep = False
                                            unsupported_reasons.append(f"Interface has {fc_tag}")
                                        elif fc_tag == "output-list":
                                            is_rep = False
                                            unsupported_reasons.append("Interface has output-list")

            iface_dict = {
                "interfaceName": display_if,
                "interfaceType": if_type,
                "unit": unit_name,
                "inboundAcl": in_acl,
                "outboundAcl": out_acl,
                "isRepresentable": is_rep,
                "unsupportedReasons": unsupported_reasons,
            }
            interfaces.append(iface_dict)

            if in_acl:
                bindings.append({
                    "filterName": in_acl,
                    "direction": "in",
                    "interfaceName": if_type,
                    "unit": unit_name,
                    "displayInterface": display_if,
                    "isRepresentable": is_rep,
                    "unsupportedReasons": unsupported_reasons,
                })
            if out_acl:
                bindings.append({
                    "filterName": out_acl,
                    "direction": "out",
                    "interfaceName": if_type,
                    "unit": unit_name,
                    "displayInterface": display_if,
                    "isRepresentable": is_rep,
                    "unsupportedReasons": unsupported_reasons,
                })

    interfaces.sort(key=lambda x: x["interfaceName"])
    fingerprint = compute_bindings_fingerprint(interfaces)

    return {
        "interfaces": interfaces,
        "bindings": bindings,
        "fingerprint": fingerprint,
    }


def find_filter_references(filter_name: str, interfaces_xml_or_parsed: str | ET.Element | dict) -> list[dict]:
    """Find all interface bindings referencing filter_name."""
    if isinstance(interfaces_xml_or_parsed, dict) and "interfaces" in interfaces_xml_or_parsed:
        parsed = interfaces_xml_or_parsed
    else:
        parsed = parse_juniper_interface_bindings(interfaces_xml_or_parsed)

    target_name = str(filter_name).strip()
    refs: list[dict] = []

    for iface in parsed["interfaces"]:
        if iface.get("inboundAcl") == target_name:
            refs.append({"interface": iface["interfaceName"], "direction": "in"})
        if iface.get("outboundAcl") == target_name:
            refs.append({"interface": iface["interfaceName"], "direction": "out"})

    return refs


def build_juniper_replace_interface_bindings_payload(
    acl_name: str,
    inbound_interfaces: list[str],
    outbound_interfaces: list[str],
    reference_config: str | None = None,
    revision: str | None = None,
) -> str:
    """Build NETCONF XML payload to atomic update interface filter bindings for acl_name."""
    if not acl_name or not str(acl_name).strip():
        raise ValueError("acl_name cannot be empty")
    acl_name = str(acl_name).strip()

    # Validate duplicates in input lists
    inbound_set = set()
    for if_name in inbound_interfaces or []:
        s = str(if_name).strip()
        if not s:
            continue
        if s in inbound_set:
            raise ValueError(f"Duplicate interface in inbound: '{s}'")
        inbound_set.add(s)

    outbound_set = set()
    for if_name in outbound_interfaces or []:
        s = str(if_name).strip()
        if not s:
            continue
        if s in outbound_set:
            raise ValueError(f"Duplicate interface in outbound: '{s}'")
        outbound_set.add(s)

    existing_interfaces: dict[str, dict] = {}
    if reference_config:
        parsed = parse_juniper_interface_bindings(reference_config)
        existing_interfaces = {i["interfaceName"]: i for i in parsed["interfaces"]}

        # Check revision / conflict
        if revision and revision.strip() and revision.strip() != parsed["fingerprint"]:
            raise ValueError(
                "ACL_BINDING_CONCURRENT_MODIFICATION: Interface bindings changed after the form was opened."
            )

        # Validate existence, collisions, and brownfield protection
        for if_name in inbound_set:
            if if_name not in existing_interfaces:
                raise ValueError(f"ACL_INTERFACE_NOT_FOUND: Interface '{if_name}' does not exist on device")
            current = existing_interfaces[if_name]
            old_in = current.get("inboundAcl")
            if old_in and old_in != acl_name:
                raise ValueError(
                    f"ACL_INTERFACE_DIRECTION_IN_USE: Interface '{if_name}' inbound is already used by filter '{old_in}'"
                )
            if not current["isRepresentable"]:
                raise ValueError(
                    f"ACL_BINDING_UNSUPPORTED: Interface '{if_name}' has unsupported brownfield configuration"
                )

        for if_name in outbound_set:
            if if_name not in existing_interfaces:
                raise ValueError(f"ACL_INTERFACE_NOT_FOUND: Interface '{if_name}' does not exist on device")
            current = existing_interfaces[if_name]
            old_out = current.get("outboundAcl")
            if old_out and old_out != acl_name:
                raise ValueError(
                    f"ACL_INTERFACE_DIRECTION_IN_USE: Interface '{if_name}' outbound is already used by filter '{old_out}'"
                )
            if not current["isRepresentable"]:
                raise ValueError(
                    f"ACL_BINDING_UNSUPPORTED: Interface '{if_name}' has unsupported brownfield configuration"
                )

    # Compute changes per (if_type, unit)
    changes: dict[tuple[str, str], dict[str, str | None]] = {}

    def get_parts(if_str: str) -> tuple[str, str]:
        if if_str in existing_interfaces:
            return existing_interfaces[if_str]["interfaceType"], existing_interfaces[if_str]["unit"]
        if "." in if_str:
            t, u = if_str.rsplit(".", 1)
            return t, u
        return if_str, "0"

    # 1. Existing bindings to remove if not in desired sets
    for if_name, if_data in existing_interfaces.items():
        key = (if_data["interfaceType"], if_data["unit"])
        if if_data.get("inboundAcl") == acl_name and if_name not in inbound_set:
            changes.setdefault(key, {})["remove_in"] = True
        if if_data.get("outboundAcl") == acl_name and if_name not in outbound_set:
            changes.setdefault(key, {})["remove_out"] = True

    # 2. Desired bindings to add
    for if_name in inbound_set:
        key = get_parts(if_name)
        old_in = existing_interfaces.get(if_name, {}).get("inboundAcl")
        if old_in != acl_name:
            changes.setdefault(key, {})["add_in"] = True

    for if_name in outbound_set:
        key = get_parts(if_name)
        old_out = existing_interfaces.get(if_name, {}).get("outboundAcl")
        if old_out != acl_name:
            changes.setdefault(key, {})["add_out"] = True

    if not changes:
        return f'<interfaces xmlns="{NS_INTERFACES}"/>'

    # Build XML
    interface_xml_parts: list[str] = []
    # Group by if_type
    grouped_by_type: dict[str, list[tuple[str, dict]]] = {}
    for (if_type, unit), ops in changes.items():
        grouped_by_type.setdefault(if_type, []).append((unit, ops))

    for if_type in sorted(grouped_by_type):
        unit_xml_parts: list[str] = []
        for unit, ops in sorted(grouped_by_type[if_type], key=lambda x: int(x[0]) if x[0].isdigit() else x[0]):
            filter_children = []
            if ops.get("add_in"):
                filter_children.append(f"<input><filter-name>{escape(acl_name)}</filter-name></input>")
            elif ops.get("remove_in"):
                filter_children.append(f'<input xmlns:nc="{NS_RPC}" nc:operation="remove"/>')

            if ops.get("add_out"):
                filter_children.append(f"<output><filter-name>{escape(acl_name)}</filter-name></output>")
            elif ops.get("remove_out"):
                filter_children.append(f'<output xmlns:nc="{NS_RPC}" nc:operation="remove"/>')

            if filter_children:
                filter_xml = "".join(filter_children)
                unit_xml_parts.append(f"""
        <unit>
          <name>{escape(unit)}</name>
          <family>
            <inet>
              <filter>
                {filter_xml}
              </filter>
            </inet>
          </family>
        </unit>""")

        if unit_xml_parts:
            units_xml = "".join(unit_xml_parts)
            interface_xml_parts.append(f"""
      <interface>
        <name>{escape(if_type)}</name>
        {units_xml}
      </interface>""")

    interfaces_xml = "".join(interface_xml_parts)
    return f"""
<interfaces xmlns="{NS_INTERFACES}">
  {interfaces_xml}
</interfaces>"""


def inspect_filter_term_count(acl_name: str, live_acl_xml: str | ET.Element) -> dict:
    """Inspect live firewall config to count terms in acl_name and list term names."""
    if isinstance(live_acl_xml, str):
        if not live_acl_xml or not live_acl_xml.strip():
            return {"filter_exists": False, "term_count": 0, "term_names": []}
        root = safe_fromstring(live_acl_xml)
    else:
        root = live_acl_xml

    target_filter_el = None
    target_name = str(acl_name).strip()

    for el in root.iter():
        if _local_name(el.tag) == "filter":
            for child in el:
                if _local_name(child.tag) == "name" and (child.text or "").strip() == target_name:
                    target_filter_el = el
                    break
            if target_filter_el is not None:
                break

    if target_filter_el is None:
        return {"filter_exists": False, "term_count": 0, "term_names": []}

    term_names = []
    for child in target_filter_el:
        if _local_name(child.tag) == "term":
            t_name_el = child.find("name")
            if t_name_el is None:
                for tc in child:
                    if _local_name(tc.tag) == "name":
                        t_name_el = tc
                        break
            if t_name_el is not None and t_name_el.text:
                term_names.append(t_name_el.text.strip())

    return {
        "filter_exists": True,
        "term_count": len(term_names),
        "term_names": term_names,
    }


def build_juniper_delete_acl_term_payload(acl_name: str, term_name: str) -> str:
    """Delete a single term from a filter."""
    return f"""
<firewall xmlns="{NS_FIREWALL}">
  <family>
    <inet>
      <filter>
        <name>{escape(acl_name)}</name>
        <term xmlns:nc="{NS_RPC}" nc:operation="remove">
          <name>{escape(term_name)}</name>
        </term>
      </filter>
    </inet>
  </family>
</firewall>"""


def build_juniper_remove_acl_payload(acl_name: str) -> str:
    """Delete an entire filter."""
    return f"""
<firewall xmlns="{NS_FIREWALL}">
  <family>
    <inet>
      <filter xmlns:nc="{NS_RPC}" nc:operation="remove">
        <name>{escape(acl_name)}</name>
      </filter>
    </inet>
  </family>
</firewall>"""


def resolve_juniper_safe_delete(
    name: str,
    term_name: str | None,
    live_acl_xml: str | ET.Element,
    live_interfaces_xml: str | ET.Element,
    revision: str | None = None,
) -> dict:
    """Determine safe delete action and return XML payload or raise error if in use or revision mismatch."""
    if isinstance(live_acl_xml, str):
        if not live_acl_xml or not live_acl_xml.strip():
            root = ET.Element("empty")
        else:
            root = safe_fromstring(live_acl_xml)
    else:
        root = live_acl_xml

    target_filter_el = None
    target_name = str(name).strip()
    for el in root.iter():
        if _local_name(el.tag) == "filter":
            for child in el:
                if _local_name(child.tag) == "name" and (child.text or "").strip() == target_name:
                    target_filter_el = el
                    break
            if target_filter_el is not None:
                break

    if target_filter_el is None:
        raise ValueError(f"ACL_FILTER_NOT_FOUND: Firewall Filter '{name}' not found on device")

    # Verify revision if provided
    current_rev = compute_filter_fingerprint(target_filter_el)
    if revision and revision.strip() and revision.strip() != current_rev:
        raise ValueError(
            f"ACL_CONCURRENT_MODIFICATION: Firewall Filter '{name}' was modified by device or another user. Please refresh and review before editing again"
        )

    term_info = inspect_filter_term_count(name, root)

    if term_name is not None and str(term_name).strip():
        target_term = str(term_name).strip()
        if target_term not in term_info["term_names"]:
            raise ValueError(f"ACL_TERM_NOT_FOUND: Term '{target_term}' not found in Firewall Filter '{name}'")

        # Check if target term is an unsupported brownfield term
        for child in target_filter_el:
            if _local_name(child.tag) == "term":
                t_name_el = child.find("name")
                if t_name_el is None:
                    for tc in child:
                        if _local_name(tc.tag) == "name":
                            t_name_el = tc
                            break
                if t_name_el is not None and (t_name_el.text or "").strip() == target_term:
                    inspected = inspect_juniper_term(child)
                    if not inspected["isRepresentable"]:
                        raise ValueError(
                            f"ACL_UNSUPPORTED_BROWNFIELD_CHANGE: Term '{target_term}' has configurations not supported by the form and cannot be edited or deleted here"
                        )

        if term_info["term_count"] > 1:
            # More than 1 term: delete only this term
            return {
                "action": "delete_term",
                "payload_xml": build_juniper_delete_acl_term_payload(name, target_term),
            }

    # Last term or empty filter: must delete entire filter, but check bindings first!
    refs = find_filter_references(name, live_interfaces_xml)
    if refs:
        bindings_str = ", ".join(
            [f"{r['interface']} ({'Inbound' if r['direction'] == 'in' else 'Outbound'})" for r in refs]
        )
        raise ValueError(
            f"ACL_FILTER_IN_USE: Cannot delete Firewall Filter '{name}' because it is in use on {bindings_str}. Please unapply it first"
        )

    return {
        "action": "delete_filter",
        "payload_xml": build_juniper_remove_acl_payload(name),
    }
