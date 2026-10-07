// |====== Known Services Format ======|

// service ที่รู้จัก (ชื่อ/port/protocol) - ใช้ทั้งตอนเลือก service ใน form
// (Port Forwarding) และตอนแสดงผล hit-count (Security Status) เพื่อแปล
// protocol+port ดิบจากอุปกรณ์กลับเป็นชื่อที่คนอ่านง่าย - เป็นชุดเดียวที่ผู้ใช้
// ยืนยันแล้วตอนทำ Port Forwarding ไม่ได้เพิ่ม entry ใหม่เพิ่มเติมเอง
// Array รายการ Know Service เรียกใช้ในกลุ่ม firewall ที่ต้องการกำหนด service
export const KNOWN_SERVICES = [
  { name: "HTTP", port: 80, protocol: "tcp" },
  { name: "HTTPS", port: 443, protocol: "tcp" },
  { name: "SSH", port: 22, protocol: "tcp" },
  { name: "FTP", port: 21, protocol: "tcp" },
  { name: "Telnet", port: 23, protocol: "tcp" },
  { name: "SMTP", port: 25, protocol: "tcp" },
  { name: "DNS", port: 53, protocol: "udp" },
  { name: "POP3", port: 110, protocol: "tcp" },
  { name: "IMAP", port: 143, protocol: "tcp" },
  { name: "SNMP", port: 161, protocol: "udp" },
  { name: "RDP", port: 3389, protocol: "tcp" },
  { name: "MySQL", port: 3306, protocol: "tcp" },
  { name: "PostgreSQL", port: 5432, protocol: "tcp" },
  { name: "SIP", port: 5060, protocol: "udp" },
];

// ทางกลับ: protocol+port ดิบ (จาก oper data ของอุปกรณ์) -> ชื่อที่รู้จัก ถ้าไม่รู้จัก
// คืน "<protocol>/<port>" ตรงๆ (ไม่เดาชื่อใหม่ที่ไม่มีใน KNOWN_SERVICES)
export function serviceNameFor(protocol, port) {
  if (!port) return protocol || "any";
  const known = KNOWN_SERVICES.find(
    (service) => service.protocol === protocol && service.port === port
  );
  if (known) return known.name;
  return protocol ? `${protocol}/${port}` : `${port}`;
}
