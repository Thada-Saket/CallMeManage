# Reusable IPv4 input

```jsx
import IPv4Input from "./components/common/IPv4Input";
import {validateIPv4Input} from "./utils/ipv4Input.js";

const [address, setAddress] = useState("");

<IPv4Input
  mode="cidr"
  value={address}
  onChange={(nextValue, validation) => setAddress(nextValue)}
  label="Interface IP"
  required
/>

// Also validate before calling the API, especially for custom form submission.
const checked = validateIPv4Input(address, {mode: "cidr", required: true});
if (!checked.valid) throw new Error(checked.error);
// checked.value is the complete address/prefix string; checked.prefix is numeric.
```

Modes: `address`, `cidr`, `subnet`, `wildcard` (IPv4 only).

The `cidr` mode displays separate IP address and prefix boxes with a fixed slash
between them. The surrounding form supplies the visible field label while the
segment inputs retain accessible labels. Validation errors highlight the affected
address or prefix frame in red without adding text below the field; the error text
remains available to assistive technology. Prefix remains required when any address is entered;
there is no automatic prefix default. A missing prefix reports an error on the
prefix input and focuses it on invalid form submission. Whole CIDR paste and
the controlled string/onChange contract remain unchanged.
All values/callbacks are strings. Drafts may be incomplete, e.g. `192..2./`.
Never send a draft unless validation is valid and complete (or explicitly allowed empty).
An empty value means unset, not `0.0.0.0`; consumers decide whether that means deletion.

Options: `required` (component default false, validator default true), `networkOnly`
and `hostOnly` (CIDR), `contiguousWildcard` (wildcard), `disabled`, `readOnly`,
`id`, `name`, `label`, external `error`, `onBlur(value, validation)`.
`name` produces a hidden field with the full string. `id` targets the first octet
and may be used by an external label. Error messages link to all segment inputs.

Dots/slash are fixed. Tab, arrows, Backspace, dot/slash navigation, full-address
paste and segment paste work. Arbitrary characters, oversized segments, leading
zeros, decimals and scientific notation are rejected, not stripped or clamped.
Paste of an address into CIDR mode preserves the existing prefix.
Partial CIDR values require completing the prefix before submission.

Subnet masks require contiguous 1 bits followed by 0 bits. Wildcards do not
require contiguity unless requested (ACLs may legitimately use scattered bits).
`hostOnly` excludes network/broadcast below /31, but allows /31 and /32.
Network/gateway/range relationships, unicast requirements, reserved addresses,
vendor-specific support and IPv6 remain the responsibility of the calling form/API.

Backend equivalents are in `tools/ipv4_input.py`: `validate_address`,
`validate_prefix`, `validate_subnet`, `validate_wildcard`, `validate_cidr`.
They return validated values or raise `ValueError`. Network/host policy is opt-in.
Do not rely on the frontend alone; API callers can bypass it.

Existing forms are not all migrated to this component yet. The legacy CIDR parser
now validates addresses, and Cisco interface writes reject malformed IPs before XML.
