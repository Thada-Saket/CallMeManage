import ipaddress
import re


def validate_dhcp_network_gateway(network, gateway):
    if not isinstance(network, str) or not re.fullmatch(r"[^/]+/\d{1,2}", network.strip()):
        raise ValueError("DHCP network must be an IPv4 network address in CIDR format")
    subnet = ipaddress.IPv4Network(network.strip(), strict=True)
    if subnet.prefixlen > 30:
        raise ValueError("DHCP network must have usable addresses for gateway and clients; /31 and /32 are unsupported")
    address = ipaddress.IPv4Address(gateway.strip())
    if address not in subnet:
        raise ValueError("Gateway must be inside the DHCP network")
    if address in (subnet.network_address, subnet.broadcast_address):
        raise ValueError("Gateway must be a host address, not the network or broadcast address")
    return subnet, address


def range_exclusions(network, start_address=None, end_address=None):
    """Convert optional client range endpoints to the legacy exclusion format."""
    start = "" if start_address is None else start_address.strip()
    end = "" if end_address is None else end_address.strip()
    if not start and not end:
        return []
    if not start or not end:
        raise ValueError("Both start_address and end_address are required")
    low = ipaddress.IPv4Address(start)
    high = ipaddress.IPv4Address(end)
    first = int(network.network_address) + 1
    last = int(network.broadcast_address) - 1
    if not first <= int(low) <= int(high) <= last:
        raise ValueError("Address range must be ordered and inside the usable DHCP network")
    excluded = []
    if first < int(low):
        excluded.append(f"{ipaddress.IPv4Address(first)}-{ipaddress.IPv4Address(int(low) - 1)}")
    if int(high) < last:
        excluded.append(f"{ipaddress.IPv4Address(int(high) + 1)}-{ipaddress.IPv4Address(last)}")
    return excluded
