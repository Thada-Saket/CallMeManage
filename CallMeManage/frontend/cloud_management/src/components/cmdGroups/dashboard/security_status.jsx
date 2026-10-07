import DismissibleError from "../../DismissibleError";
import getDeviceInformation from "../../../hooks/getDeviceInformation";
import { serviceNameFor } from "../../../utils/knownServices";
import { Reload_Result } from "../../commandResult/reload_command_result";

function ensureArray(value) {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

// protocol เก็บเป็นเลข IANA (ไม่ใช่ชื่อ) ใน oper data - map กลับเป็นชื่อเท่าที่ระบบ
// นี้เขียนได้จริง (set_acl_rule/create_nat_policy/create_firewall_policy ใช้แค่
// ip/tcp/udp/icmp/gre/esp/ahp/ospf/igmp ผ่าน _ACL_NAMED_PROTOCOLS) เลขอื่นที่ไม่รู้จัก
// โชว์ "proto <n>" ตรงๆ ไม่เดาชื่อ
const PROTOCOL_NAMES = { 1: "icmp", 2: "igmp", 6: "tcp", 17: "udp", 47: "gre", 50: "esp", 51: "ahp", 89: "ospf" };

function protocolLabel(protocol) {
  if (!protocol || "any" in protocol) return "any";
  if (protocol.number !== undefined) {
    const num = Number(protocol.number);
    return PROTOCOL_NAMES[num] || `proto ${num}`;
  }
  return "any";
}

// destination-port เป็น choice (Cisco-IOS-XE-acl-oper.yang: acl-port) - port-any
// (ไม่จำกัด port) หรือ port-configured -> port-data{port-operator, ports} - คืน
// null ถ้าไม่จำกัด port (ให้ caller โชว์แค่ protocol เฉยๆ)
function destinationPortLabel(destinationPort) {
  if (!destinationPort || "any" in destinationPort) return null;
  const data = destinationPort["port-data"];
  if (!data) return null;
  const ports = ensureArray(data.ports).map(Number);
  const operator = data["port-operator"];
  if (ports.length === 0) return null;
  if (operator === "range" && ports.length === 2) return `${ports[0]}-${ports[1]}`;
  if (operator === "not-equals") return `!= ${ports[0]}`;
  if (operator === "lesser-than") return `< ${ports[0]}`;
  if (operator === "greater-than") return `> ${ports[0]}`;
  return ports[0]; // equals (ค่าปกติที่ set_acl_rule/create_nat_policy/create_firewall_policy ใช้)
}

// ดึง hit-count ต่อ ACE จาก access-lists (Cisco-IOS-XE-acl-oper.yang) - โครงสร้าง
// ตรงกับที่ verify ไว้: access-list-entries-rule-data เป็น choice ระหว่าง
// v4-standard/v4-extended/v4-role-based/v6/v6-role-based - ทุกอย่างที่สร้างผ่าน
// เว็บนี้ (set_acl_rule/create_nat_policy/create_firewall_policy) เป็น extended
// ACL ทั้งหมด เลยอ่านแค่ v4-extended-ace-rule เป็นหลัก แบบอื่นยังไม่เคย verify
// จากอุปกรณ์จริง (ไม่เดาโครงสร้าง ปล่อย service/action ว่างถ้าเจอ)
function parseAclHitCounts(result) {
  try {
    const acls = ensureArray(result?.payload?.data?.["access-lists"]?.["access-list"]);
    return acls.map((acl) => {
      const entries = ensureArray(acl?.["access-list-entries"]?.["access-list-entry"]);
      const rows = entries.map((entry) => {
        const ruleData = entry?.["access-list-entries-rule-data"] || {};
        const rule = ruleData["v4-extended-ace-rule"] || ruleData["v4-standard-ace-rule"] || null;
        const protocol = rule ? protocolLabel(rule.protocol) : "";
        const port = rule ? destinationPortLabel(rule["destination-port"]) : null;
        return {
          service: rule ? serviceNameFor(protocol, port) : "-",
          action: rule?.action || "",
          hitCount: entry?.["access-list-entries-oper-data"]?.["match-counter"] ?? "0",
        };
      });
      return { name: acl?.["access-control-list-name"] || "", entries: rows };
    });
  } catch {
    return null;
  }
}

// ดึง hit-count ต่อ zone-pair จาก zbfw (Cisco-IOS-XE-fw-oper.yang) - zonepair-name
// เป็นชื่อ policy ที่ผู้ใช้ตั้ง (create_firewall_policy's `name`) ส่วน class-name
// ที่ผูกกับ zone-pair นั้นเป็น "FW_<name>" เสมอ (ดู create_firewall_policy) ตัด
// prefix ออกให้อ่านง่ายขึ้น - class-action/pkts-counter มาจากอุปกรณ์ตรงๆ
function parseZbfHitCounts(result) {
  try {
    const pairs = ensureArray(result?.payload?.data?.zbfw?.["zonepair-statistics"]);
    return pairs.map((pair) => {
      const classes = ensureArray(pair?.["fw-traffic-class-entry"]);
      const rows = classes.map((cls) => ({
        service: (cls?.["class-name"] || "").replace(/^FW_/, "") || "-",
        action: cls?.["class-action"] || "",
        hitCount: cls?.["pkts-counter"] ?? "0",
      }));
      return { name: pair?.["zonepair-name"] || "", entries: rows };
    });
  } catch {
    return null;
  }
}

// Junos's get_security_status() คืนโครงสร้างเดียวกับ get_firewall_information()
// ตรงๆ (security/zones+policies - config view) เพราะยังไม่เคย verify RPC
// operational ที่มี hit-count จริง (get-security-policies-information) กับ
// อุปกรณ์จริงเลย - ไม่มี hit count ให้โชว์จริงๆ เลยไม่บังคับข้อมูลนี้ให้เข้ารูป
// ตาราง hit-count (จะได้ hitCount="0" มั่วๆ ทุกแถวซึ่งเข้าใจผิดได้ว่ามีข้อมูลจริง)
// - โชว์เป็นตาราง policy config ตรงๆ แยกจากกันแทน พร้อม note ว่าไม่มี hit count
function parseJuniperPolicyList(result) {
  const policyPairs = ensureArray(result?.payload?.data?.configuration?.security?.policies?.policy);
  const rows = [];
  for (const pair of policyPairs) {
    const fromZone = pair?.["from-zone-name"] || "";
    const toZone = pair?.["to-zone-name"] || "";
    for (const rule of ensureArray(pair?.policy)) {
      const then = rule?.then || {};
      let action = "";
      if ("permit" in then) action = "permit";
      else if ("deny" in then) action = "deny";
      rows.push({ name: rule?.name || "", source: fromZone, destination: toZone, action });
    }
  }
  return rows;
}

function JuniperPolicyTable({ rows }) {
  return (
    <div className="security-table-container">
      <p style={{ color: "var(--text-muted)" }}>
        Junos does not yet provide hit-count statistics via operational RPC; this table displays configured security policies.
      </p>
      {rows.length === 0 ? (
        <div className="config-placeholder">No security policies configured</div>
      ) : (
        <table className="security-data-table">
          <caption>Security Policy</caption>
          <thead>
            <tr>
              <th>No</th>
              <th>Policy Name</th>
              <th>From Zone</th>
              <th>To Zone</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row, index) => (
              <tr key={`${row.name}-${index}`}>
                <td>{index + 1}</td>
                <td>{row.name || "-"}</td>
                <td>{row.source || "-"}</td>
                <td>{row.destination || "-"}</td>
                <td>{row.action || "-"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function HitCountTable({ caption, columnLabel, rows }) {
  if (rows.length === 0) {
    return <div className="config-placeholder">No data for {caption}</div>;
  }
  return (
    <table className="security-data-table">
      <caption>{caption}</caption>
      <thead>
        <tr>
          <th>No</th>
          <th>{columnLabel}</th>
          <th>Match Service</th>
          <th>Action</th>
          <th>Hit Count</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((row, index) => (
          <tr key={`${row.name}-${index}`}>
            <td>{index + 1}</td>
            <td>{row.name || "-"}</td>
            <td>
              {row.entries.length === 0 ? (
                "-"
              ) : (
                <ul>
                  {row.entries.map((entry, entryIndex) => (
                    <li key={entryIndex}>{entry.service}</li>
                  ))}
                </ul>
              )}
            </td>
            <td>
              {row.entries.length === 0 ? (
                "-"
              ) : (
                <ul>
                  {row.entries.map((entry, entryIndex) => (
                    <li key={entryIndex}>{entry.action || "-"}</li>
                  ))}
                </ul>
              )}
            </td>
            <td>
              {row.entries.length === 0 ? (
                "-"
              ) : (
                <ul>
                  {row.entries.map((entry, entryIndex) => (
                    <li key={entryIndex}>{entry.hitCount}</li>
                  ))}
                </ul>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export default function SecurityStatus({ devId }) {
  const { data, loading, error, clearError, refetch } = getDeviceInformation(devId, "get_security_status");

  if (loading && !data) return <div className="center-loading">Fetching Security Status...</div>;

  const isJuniper = data?.normalized && data?.result?.vendor === "juniper";
  const juniperRows = isJuniper ? (() => {
    try {
      return parseJuniperPolicyList(data.result);
    } catch {
      return null;
    }
  })() : null;
  const aclRows = data?.normalized && !isJuniper ? parseAclHitCounts(data.result) : null;
  const zbfRows = data?.normalized && !isJuniper ? parseZbfHitCounts(data.result) : null;

  return (
    <div className="command-output">
      <div className="command-output-title">
        <Reload_Result loading={loading} onRefresh={refetch}/>
      </div>

      {error && <DismissibleError message={error} onDismiss={clearError} />}

      {isJuniper ? (
        juniperRows === null ? (
          data && (
            <pre>{typeof data.result === "string" ? data.result : JSON.stringify(data.result, null, 2)}</pre>
          )
        ) : (
          <JuniperPolicyTable rows={juniperRows} />
        )
      ) : aclRows === null || zbfRows === null ? (
        data && (
          <pre>{typeof data.result === "string" ? data.result : JSON.stringify(data.result, null, 2)}</pre>
        )
      ) : (
        <div className="security-table-container">
          <HitCountTable caption="Access Control List Hit Count" columnLabel="ACL Name" rows={aclRows} />
          <HitCountTable caption="Zone Based Firewall Hit Count" columnLabel="ZBF Name" rows={zbfRows} />
        </div>
      )}
    </div>
  );
}
