import DismissibleError from "../../DismissibleError";
import IPv4Input from "../../common/IPv4Input";

const MAX_NAME_SERVERS = 6; // สูงสุดของ Cisco (leaf-list no-vrf max-elements 6)
const MIN_ROWS = 2; // โชว์ 2 ช่องเสมอ (Primary/Secondary) แบบ FortiGate

// ฟอร์ม DNS แบบ inline (ไม่ใช่ modal/ไม่แยกหน้า) - dns.jsx เป็นคน fetch ค่าสด
// มาเติมเป็น initial state แล้วส่ง values + setValue + onApply เข้ามา ตัวนี้แค่
// render controls: 2 toggle (dns server / domain lookup), 1 ช่องชื่อ domain,
// และรายการ name-server (2 ช่องแรกคงที่ เพิ่มได้ถึง 6)
export default function DnsForm({ values, setValue, onApply, applying, error, onDismissError, loading, onRefresh, showDnsServerToggle = true }) {
  // โชว์อย่างน้อย MIN_ROWS ช่องเสมอ - เติมช่องว่างให้ครบถ้ามีน้อยกว่า
  const rows = [...values.nameServers];
  while (rows.length < MIN_ROWS) rows.push("");

  function setServerAt(index, ip) {
    const next = [...rows];
    next[index] = ip;
    setValue("nameServers", next);
  }

  function addServer() {
    if (rows.length >= MAX_NAME_SERVERS) return;
    setValue("nameServers", [...rows, ""]);
  }

  function removeServerAt(index) {
    // ลบได้เฉพาะช่องที่เกิน 2 ช่องแรก (Primary/Secondary คงไว้เสมอ)
    if (index < MIN_ROWS) return;
    setValue("nameServers", rows.filter((_, i) => i !== index));
  }

  const serverLabel = (index) => {
    if (index === 0) return "Primary DNS Server";
    if (index === 1) return "Secondary DNS Server";
    return `DNS Server ${index + 1}`;
  };

  return (
    <form
      className="interface-configuration-form"
      onSubmit={(event) => {
        event.preventDefault();
        onApply();
      }}
    >
      {error && <DismissibleError message={error} onDismiss={onDismissError} />}

      {showDnsServerToggle && (
        <div className="interface-configuration-form-field">
          <label className="data-label">Enable DNS Server (Router act as DNS server)</label>
          <div className="toggle-switch-container">
            <input
              type="checkbox"
              id="dns-server-toggle"
              checked={values.dnsServer}
              onChange={(event) => setValue("dnsServer", event.target.checked)}
            />
            <label className="toggleSwitch" htmlFor="dns-server-toggle"></label>
          </div>
        </div>
      )}

      <div className="interface-configuration-form-field">
        <label className="data-label">Enable Domain Lookup</label>
        <div className="toggle-switch-container">
          <input
            type="checkbox"
            id="domain-lookup-toggle"
            checked={values.domainLookup}
            onChange={(event) => setValue("domainLookup", event.target.checked)}
          />
          <label className="toggleSwitch" htmlFor="domain-lookup-toggle"></label>
        </div>
      </div>

      <div className="interface-configuration-form-field-third">
        <label className="data-label">Domain Name</label>
        <input
          type="text"
          placeholder="example.com"
          value={values.domainName}
          onChange={(event) => setValue("domainName", event.target.value)}
        />
        
      </div>

      {rows.map((ip, index) => (
        <div className="interface-configuration-form-field-third" key={index}>
          <label className="data-label" htmlFor={`dns-server-${index}`}>{serverLabel(index)}</label>
          <IPv4Input
            id={`dns-server-${index}`}
            label={serverLabel(index)}
            value={ip}
            onChange={(value) => setServerAt(index, value)}
          />
          {serverLabel(index) === "Primary DNS Server" && (
              rows.length < MAX_NAME_SERVERS && (
                <button type="button" className="mini-btn btn-ghost" onClick={addServer}>
                  +
                </button>
              )
          )}
          {index >= MIN_ROWS && (
            <button
              type="button"
              className="mini-btn btn-ghost"
              onClick={() => removeServerAt(index)}
            >
                -
            </button>
          )}
        </div>
      ))}

      <div className="interface-form-btn-container">
        <button type="submit" className="btn btn-primary" disabled={applying}>
          {applying ? "Applying..." : "Apply"}
        </button>
        <button type="button" className="btn btn-ghost" disabled={loading} onClick={onRefresh}>
            {loading ? "Refreshing..." : "Refresh"}
        </button>
      </div>
    </form>
  );
}
