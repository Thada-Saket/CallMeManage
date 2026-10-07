import { validateIPv4Input } from "./ipv4Input.js";

const toNumber = (address) => address.split(".").reduce((number, octet) => number * 256 + Number(octet), 0);

// รูปแบบ IPv4/CIDR ทั้งหมดตัดสินโดย validateIPv4Input (source of truth) ที่นี่เหลือ
// เฉพาะกฎธุรกิจของ DHCP pool: ห้าม /31 และ /32
export function validateDhcpNetwork(network) {
  const format = validateIPv4Input(network, { mode: "cidr", required: true });
  if (!format.valid) return `Network: ${format.error}, e.g. 192.168.1.0/24`;
  if (format.prefix > 30) return "DHCP pool requires a Gateway and client IPs; /31 and /32 are not supported";
  const checked = validateIPv4Input(network, { mode: "cidr", required: true, networkOnly: true });
  if (!checked.valid) return "Network must be the network address of the subnet, not a host IP, e.g. 192.168.1.0/24";
  return null;
}

export function validateDhcpGateway(network, gateway) {
  if (validateDhcpNetwork(network)) return "Please verify the Network first";
  const checked = validateIPv4Input(gateway, { mode: "address", required: true });
  if (!checked.valid) return `Gateway must be a valid IPv4 address, e.g. 192.168.1.1 (${checked.error})`;
  const address = toNumber(checked.address);
  const network_ = validateIPv4Input(network, { mode: "cidr", required: true });
  const first = toNumber(network_.address);
  const last = first + 2 ** (32 - network_.prefix) - 1;
  if (address < first || address > last) return "Gateway must be within the Network subnet";
  if (address === first || address === last) return "Gateway must be a host IP, not a network or broadcast address";
  return null;
}
