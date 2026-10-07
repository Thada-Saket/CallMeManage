import { createContext, useContext } from "react";

// |====== Device Capability Context ======|

// (dynamic feature ขั้นที่ 5) คำสั่งที่ backend ตัดสินว่าอุปกรณ์นี้ทำไม่ได้ - DeviceDetail.jsx เป็นผู้ให้ค่า
// hiddenCommands / hiddenOptions มีค่าเฉพาะเมื่อ backend เปิดการกรองอยู่ (capability.enforced) ตอนปิดสวิตช์
// ยังโหลดไม่เสร็จ หรือโหลดไม่ได้ จะว่างเสมอ ทุกหน้าจึงทำงานเหมือนเดิม
const EMPTY_COMMANDS = new Set();
const EMPTY_OPTIONS = {};

export const DeviceCapabilityContext = createContext({ hiddenCommands: EMPTY_COMMANDS, hiddenOptions: EMPTY_OPTIONS });

export function useDeviceCapability() {
  return useContext(DeviceCapabilityContext);
}

export function hiddenCommandsFrom(capability) {
  if (!capability?.enforced || !Array.isArray(capability.hidden)) return EMPTY_COMMANDS;
  return new Set(capability.hidden.map((item) => item.command));
}

// ค่าพารามิเตอร์ที่อุปกรณ์ทำไม่ได้ทั้งที่คำสั่งยังใช้ได้ เช่น create_security_tunnel ที่ tunnel_type = "ipsec"
// บน c9000 · รูปแบบจาก backend: { คำสั่ง: { พารามิเตอร์: { ค่า: [เหตุผล] } } }
export function hiddenOptionsFrom(capability) {
  const options = capability?.hidden_options;
  if (!capability?.enforced || !options || typeof options !== "object" || Array.isArray(options)) return EMPTY_OPTIONS;
  return options;
}

export function isOptionHidden(hiddenOptions, command, parameter, value) {
  return Boolean(hiddenOptions?.[command]?.[parameter]?.[value]);
}
