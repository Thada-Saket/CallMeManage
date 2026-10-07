import { runDeviceCommand } from "../../../api/api_devices";
import { splitInterfaceName } from "../../../utils/interfaceName";
import {parseJuniperStaticNat} from "./juniperStaticNatParser";
import { parseJuniperPortForwards } from "./juniperPortForwardParser";
import { proxyArpAddressesEqual, proxyArpBindings } from "./proxyArpBindings";

// เจอบั๊กจริง (2026-07-30 รอบ 4 - user ชี้): ลบ static NAT/port forward แล้ว
// proxy-arp entry ของ public IP นั้นไม่เคยถูกลบตามเลย (ตั้งใจไว้แต่แรกว่าไม่แตะ
// - อาจแชร์ public IP เดียวกันกับ rule อื่นอยู่ ลบตามไม่ปลอดภัยถ้าไม่เช็คก่อน)
// แต่ผลจริงคือ entry ค้างเป็น orphan ถาวร ไม่มีทางลบออกได้เลยผ่านหน้าเว็บ - เช็ค
// ก่อนลบจริงว่ายังมี rule อื่นใช้ public IP นี้อยู่หรือไม่ **ทั้ง static NAT และ
// port forward** (คนละหน้า คนละ container ใน Junos แต่แชร์ proxy-arp ร่วมกันได้
// จริง ต้องเช็กทั้งสองกลุ่มก่อนเสมอ Delete จะใช้ผลลัพธ์นี้แนบการลบ Proxy ARP
// เข้า RPC หลัก ส่วน Edit ที่ย้าย public IP เดิมยังใช้ cleanup wrapper ด้านล่าง
export function orphanedProxyArpRemoval(globalIp, staticRows, pfRows, proxyArpResult) {
  if (!globalIp) return {};
  const stillUsed = [...(staticRows || []), ...(pfRows || [])].some((row) =>
    proxyArpAddressesEqual(row.globalIp, globalIp),
  );
  if (stillUsed) return {};

  const binding = proxyArpBindings(proxyArpResult).find((entry) =>
    proxyArpAddressesEqual(entry.address, globalIp),
  );
  if (!binding) return {};

  const { interfaceType, interfaceId } = splitInterfaceName(binding.interfaceName);
  return {
    interface_type: interfaceType,
    interface_id: interfaceId,
    // ใช้ key จริงที่อ่านจากอุปกรณ์ ไม่เดาว่าค่าถูกเก็บเป็น address หรือ /32
    proxy_arp_address: binding.address,
  };
}

// ใช้กับ Edit ที่ย้าย public IP/interface เดิมอยู่ก่อนแล้ว; Delete ไม่เรียก
// ฟังก์ชันนี้อีกต่อไป เพราะแนบผลจาก orphanedProxyArpRemoval เข้า delete RPC หลัก
// โดยตรงแล้ว
export async function cleanupOrphanedProxyArp(devId, globalIp) {
  if (!globalIp) return;

  const staticResult = await runDeviceCommand(devId, "get_static_nat_information", {});
  const pfResult = await runDeviceCommand(devId, "get_port_forward_information", {});
  // อ่านไม่ครบต้องไม่เดาว่า address เป็น orphan เพราะอาจตัด Proxy ARP ที่ rule
  // ใน feature ซึ่งอ่านล้มเหลวยังใช้อยู่
  if (!staticResult?.normalized || !pfResult?.normalized) return;

  const parameters = orphanedProxyArpRemoval(
    globalIp,
    parseJuniperStaticNat(staticResult.result),
    parseJuniperPortForwards(pfResult.result),
    staticResult.result,
  );
  if (!parameters.proxy_arp_address) return;
  await runDeviceCommand(devId, "remove_nat_proxy_arp", {
    interface_type: parameters.interface_type,
    interface_id: parameters.interface_id,
    address: parameters.proxy_arp_address,
  });
}
