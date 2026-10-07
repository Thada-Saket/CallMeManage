"""Build narrowly scoped removals from a fresh Cisco running configuration."""
import xml.etree.ElementTree as ET

NC = "urn:ietf:params:xml:ns:netconf:base:1.0"
NATIVE = "http://cisco.com/ns/yang/Cisco-IOS-XE-native"
ZONE = "http://cisco.com/ns/yang/Cisco-IOS-XE-zone"


def zone_reference_removals(config_xml: str, zone_id: str) -> str:
    try:
        root = ET.fromstring(config_xml.strip())
    except ET.ParseError as exc:
        raise ValueError("Cannot read Cisco zone references: invalid XML") from exc
    if any(el.tag == f"{{{NC}}}rpc-error" for el in root.iter()):
        raise ValueError("Device rejected reading Cisco zone references")
    natives = list(root.iter(f"{{{NATIVE}}}native"))
    if len(natives) != 1:
        raise ValueError("Cannot read Cisco zone references: native configuration missing")
    native = natives[0]

    def member_removal(entry):
        member = entry.find(f"{{{ZONE}}}zone-member")
        if member is not None and member.findtext(f"{{{ZONE}}}security") == zone_id:
            name = entry.find(f"{{{NATIVE}}}name")
            if name is None or not name.text:
                raise ValueError("Referenced interface has no configuration key")
            result = ET.Element(entry.tag)
            ET.SubElement(result, name.tag).text = name.text
            ET.SubElement(result, member.tag, {f"{{{NC}}}operation": "remove"})
            return result
        # Keep wrapper paths, including *-subinterface, rather than flattening them.
        children = [result for child in entry if (result := member_removal(child)) is not None]
        if not children:
            return None
        result = ET.Element(entry.tag)
        name = entry.find(f"{{{NATIVE}}}name")
        if name is not None:
            ET.SubElement(result, name.tag).text = name.text
        result.extend(children)
        return result

    blocks = []
    interfaces = native.find(f"{{{NATIVE}}}interface")
    if interfaces is not None:
        removal = member_removal(interfaces)
        if removal is not None:
            blocks.append(ET.tostring(removal, encoding="unicode"))
    pairs = native.find(f"{{{NATIVE}}}zone-pair")
    if pairs is not None:
        removal = ET.Element(pairs.tag)
        for pair in pairs.findall(f"{{{ZONE}}}security"):
            if zone_id not in (pair.findtext(f"{{{ZONE}}}source"), pair.findtext(f"{{{ZONE}}}destination")):
                continue
            pair_id = pair.findtext(f"{{{ZONE}}}id")
            if not pair_id:
                raise ValueError("Referenced zone-pair has no configuration key")
            item = ET.SubElement(removal, pair.tag, {f"{{{NC}}}operation": "remove"})
            ET.SubElement(item, f"{{{ZONE}}}id").text = pair_id
        if len(removal):
            blocks.append(ET.tostring(removal, encoding="unicode"))
    return "".join(blocks)
