"""Compose Cisco NTP server edits into one running edit-config RPC.

Only <native><ntp><server><server-list> instances are accepted, so the parent
<ntp> node (authentication, source-interface, peers, ...) is never replaced.
Never emulates atomicity with sequential running writes.
"""
from copy import deepcopy
from xml.etree import ElementTree as ET

from tools.safe_xml import safe_fromstring
from backend.interface_atomic import NATIVE, NC, OP, combine_cisco_interface_edits

NTP_NS = "http://cisco.com/ns/yang/Cisco-IOS-XE-ntp"
ALLOWED_OPERATIONS = (None, "remove", "delete", "merge", "create")


def _parse_edit(payload):
    try:
        root = safe_fromstring(payload.strip())
    except ET.ParseError as exc:
        raise ValueError(f"Invalid NETCONF payload: {exc}") from exc
    edit = root.find(f"{{{NC}}}edit-config")
    if edit is None:
        raise ValueError("Atomic transaction requires edit-config")
    fragment = edit.find(f"{{{NC}}}config")
    native = fragment.find(f"{{{NATIVE}}}native") if fragment is not None else None
    if native is None or len(fragment) != 1:
        raise ValueError("Atomic Cisco transaction requires a single native root")
    return root, edit, fragment, native


def is_cisco_ntp_edit(payload) -> bool:
    try:
        native = _parse_edit(payload)[3]
    except ValueError:
        return False
    return [child.tag for child in native] == [f"{{{NATIVE}}}ntp"]


def combine_cisco_ntp_edits(payloads):
    if not payloads:
        raise ValueError("Atomic NTP transaction must contain at least one edit")

    server_lists = []
    for payload in payloads:
        _, _, _, native = _parse_edit(payload)
        ntp = native[0] if len(native) == 1 else None
        if ntp is None or ntp.tag != f"{{{NATIVE}}}ntp" or len(ntp) != 1 or ntp.get(OP):
            raise ValueError("Only native/ntp/server edits can be combined on Cisco running")
        server = ntp[0]
        if server.tag != f"{{{NTP_NS}}}server" or server.get(OP) or not len(server):
            raise ValueError("Only native/ntp/server edits can be combined on Cisco running")
        for entry in server:
            key = entry.find(f"{{{NTP_NS}}}ip-address") if entry.tag == f"{{{NTP_NS}}}server-list" else None
            if (key is None or not (key.text or "").strip() or len(entry) != 1
                    or entry.get(OP) not in ALLOWED_OPERATIONS):
                raise ValueError("NTP edit must contain only server-list entries keyed by ip-address")
            server_lists.append(entry)

    addresses = [entry.find(f"{{{NTP_NS}}}ip-address").text.strip() for entry in server_lists]
    if len(set(addresses)) != len(addresses):
        raise ValueError("Conflicting NTP edits for the same server in one transaction")

    root, edit, fragment, native = _parse_edit(payloads[0])
    server = native[0][0]
    for child in list(server):
        server.remove(child)
    for entry in server_lists:
        server.append(deepcopy(entry))

    option = edit.find(f"{{{NC}}}error-option")
    if option is None or option.text != "rollback-on-error":
        raise ValueError("Atomic running edit requires rollback-on-error")
    target = edit.find(f"{{{NC}}}target")
    if target is None or [child.tag for child in target] != [f"{{{NC}}}running"]:
        raise ValueError("Atomic running edit must target running")
    return ET.tostring(root, encoding="unicode")


def combine_cisco_running_edits(payloads):
    """Pick the combiner by feature scope; mixed or unknown scopes are rejected."""
    if not payloads:
        raise ValueError("Transaction must contain at least one command")
    kinds = {is_cisco_ntp_edit(payload) for payload in payloads}
    if kinds == {True}:
        return combine_cisco_ntp_edits(payloads)
    if kinds == {True, False}:
        raise ValueError("NTP edits cannot be combined with other features in one Cisco running transaction")
    try:
        return combine_cisco_interface_edits(payloads)
    except ET.ParseError as exc:
        raise ValueError(f"Invalid NETCONF payload: {exc}") from exc
