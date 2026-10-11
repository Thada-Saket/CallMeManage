import getDeviceInformation from "../../../hooks/getDeviceInformation";
import { parseNatInterfaceState } from "./natTeardown";

function ensureArray(value) {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

// Cisco: Static NAT / Port Forwarding เขียนแค่ entry `ip nat inside source static ...`
// (set_static_nat / set_port_forward) ไม่ได้ตั้ง `ip nat inside/outside` บน interface เอง
// IOS จะ translate ก็ต่อเมื่อมีทั้งขา inside และ outside ซึ่งตอนนี้มีแค่หน้า NAT (Enable NAT
// -> create_nat_policy) ที่ตั้งให้ - ยังไม่เปิด NAT หรือปิด NAT ไปแล้ว = entry ยังอยู่ในตาราง
// แต่ traffic ไม่ถูก translate เลย ผู้ใช้เลือกให้เตือนแทนการตั้ง inside/outside เอง
//
// อ่านจาก get_nat_dashboard ตัวเดียวกับหน้า NAT (dedupeInFlight - ไม่ยิงซ้อนถ้าหน้าอื่น
// กำลังโหลดอยู่) ถือว่า "ใช้งานได้" เมื่อมี NAT rule และมีทั้งขา outside และ inside อย่างน้อย
// 1 ขา · อ่านไม่ได้/กำลังโหลด = ไม่แสดงแถบ (ไม่เตือนจากข้อมูลที่ไม่รู้จริง)
export function ciscoNatEnabledFromDashboard(result) {
  const source = result?.payload?.data?.native?.ip?.nat?.inside?.source;
  const hasRule = ensureArray(source?.["list-interface"]?.list).length > 0
    || ensureArray(source?.["list-pool"]?.list).length > 0;
  const { insideNames, outsideName } = parseNatInterfaceState(result?.switchport || []);
  return hasRule && Boolean(outsideName) && insideNames.length > 0;
}

export default function CiscoNatDependencyBanner({ devId, featureName }) {
  const { data } = getDeviceInformation(devId, "get_nat_dashboard", { dedupeInFlight: true });
  if (!data?.normalized || ciscoNatEnabledFromDashboard(data.result)) return null;

  return (
    <div className="nat-dependency-banner" role="status">
      <strong>NAT is not enabled on this device.</strong>{" "}
      {featureName} entries below are saved on the device but will not translate any traffic until NAT is
      enabled on the <strong>NAT</strong> page (it sets <code>ip nat inside</code> / <code>ip nat outside</code> on
      the interfaces that {featureName} relies on).
    </div>
  );
}
