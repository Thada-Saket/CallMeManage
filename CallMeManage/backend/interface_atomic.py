"""Compose interface-only Cisco edits; never emulate atomicity with sequential running writes."""
from copy import deepcopy
from xml.etree import ElementTree as ET

from tools.safe_xml import safe_fromstring
NC = "urn:ietf:params:xml:ns:netconf:base:1.0"
NATIVE = "http://cisco.com/ns/yang/Cisco-IOS-XE-native"
OP = f"{{{NC}}}operation"


def combine_cisco_interface_edits(payloads):
    def identity(node):
        local = node.tag.split("}")[-1]
        keys = {"helper-address": ("address",), "pool": ("id",),
                "low-address-list": ("low-address",),
                "low-high-address-list": ("low-address", "high-address")}.get(local, ("name",))
        return node.tag, tuple((child.tag, child.text) for child in node
                               if child.tag.split("}")[-1] in keys)

    def merge(target, incoming):
        for child in incoming:
            existing = next((entry for entry in target if identity(entry) == identity(child)), None)
            if existing is None:
                target.append(deepcopy(child))
            elif not len(child) or child.get(OP) or existing.get(OP):
                # Remove/create of the same subtree is not an atomic value update.
                if len(child) and child.tag.split("}")[-1] not in ("low-address-list", "low-high-address-list") and (child.get(OP) in ("remove", "delete") or existing.get(OP) in ("remove", "delete")):
                    if ET.tostring(existing) != ET.tostring(child):
                        raise ValueError("Conflicting remove/update in atomic interface transaction")
                # The replacement keeps the position of the node it replaces.
                # Cisco enforces RFC 7950 key-first encoding, and every interface
                # payload repeats <name>, so removing and re-appending pushed the
                # list key behind <description>/<ip> as soon as a second edit on
                # the same interface was merged. The device then rejected the whole
                # RPC with "expected tag: name, got tag: description".
                position = list(target).index(existing)
                target.remove(existing)
                target.insert(position, deepcopy(child))
            else:
                merge(existing, child)

    root = safe_fromstring(payloads[0].strip())
    edit = root.find(f"{{{NC}}}edit-config")
    if edit is None:
        raise ValueError("Atomic interface transaction requires edit-config")
    config = edit.find(f"{{{NC}}}config")
    if config is None:
        raise ValueError("Missing configuration")
    for index, payload in enumerate(payloads):
        candidate = safe_fromstring(payload.strip()).find(f"{{{NC}}}edit-config")
        if candidate is None:
            raise ValueError("Atomic interface transaction requires edit-config")
        fragment = candidate.find(f"{{{NC}}}config")
        native = fragment.find(f"{{{NATIVE}}}native") if fragment is not None else None
        if native is None or len(fragment) != 1 or any(child.tag not in (f"{{{NATIVE}}}interface", f"{{{NATIVE}}}ip") for child in native):
            raise ValueError("Only interface and DHCP edits can be combined on Cisco running")
        if index:
            merge(config, fragment)
    option = edit.find(f"{{{NC}}}error-option")
    if option is None or option.text != "rollback-on-error":
        raise ValueError("Atomic running edit requires rollback-on-error")
    return ET.tostring(root, encoding="unicode")
