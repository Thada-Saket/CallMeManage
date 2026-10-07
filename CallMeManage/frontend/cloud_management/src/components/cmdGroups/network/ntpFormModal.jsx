import DismissibleError from "../../DismissibleError";
import IPv4Input from "../../common/IPv4Input";

const MAX_NTP_SERVERS = 5;
const MIN_ROWS = 1;

export default function NtpForm({ values, setServers, onApply, applying, error, onDismissError, loading, onRefresh }) {
  const rows = [...values.servers];
  while (rows.length < MIN_ROWS) rows.push("");

  function setServerAt(index, value) {
    const next = [...rows];
    next[index] = value;
    setServers(next);
  }

  function addServer() {
    if (rows.length >= MAX_NTP_SERVERS) return;
    setServers([...rows, ""]);
  }

  function removeServerAt(index) {
    if (index === 0) {
      setServerAt(0, "");
      return;
    }
    setServers(rows.filter((_, rowIndex) => rowIndex !== index));
  }

  return (
    <form
      className="interface-configuration-form"
      onSubmit={(event) => {
        event.preventDefault();
        onApply();
      }}
    >
      {error && <DismissibleError message={error} onDismiss={onDismissError} />}

      {rows.map((server, index) => (
        <div className="interface-configuration-form-field-third" key={index}>
          <label className="data-label" htmlFor={`ntp-server-${index}`}>
            NTP Server {index + 1}
          </label>
          <IPv4Input
            id={`ntp-server-${index}`}
            label={`NTP Server ${index + 1}`}
            value={server}
            onChange={(value) => setServerAt(index, value)}
          />
          {index === 0 && rows.length < MAX_NTP_SERVERS && (
            <button type="button" className="mini-btn btn-ghost" onClick={addServer} aria-label="Add NTP server">
              +
            </button>
          )}
          {index > 0 && (
            <button
              type="button"
              className="mini-btn btn-ghost"
              onClick={() => removeServerAt(index)}
              aria-label={`Remove NTP Server ${index + 1}`}
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
        <button type="button" className="btn btn-ghost" disabled={loading || applying} onClick={onRefresh}>
          {loading ? "Refreshing..." : "Refresh"}
        </button>
      </div>
    </form>
  );
}
