from pydantic import validate_call, Field, ValidationError
import ipaddress

@validate_call
def input_prefix(
        prefix: int = Field(ge=0, le=32)
) -> str:
        network = ipaddress.IPv4Network(f'0.0.0.0/{prefix}', strict=False)
        return str(network.netmask)

def prefix_translator(
        prefix: int
) -> str:
        try:
                return input_prefix(prefix)
        except ValidationError:
                raise ValueError("Invalid Prefix")

def prefix_to_wildcard(prefix: int) -> str:
        from tools.ipv4_input import validate_prefix
        validated = validate_prefix(prefix, "prefix")
        network = ipaddress.IPv4Network(f"0.0.0.0/{validated}", strict=False)
        return str(network.hostmask)