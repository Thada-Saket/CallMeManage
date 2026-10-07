import { request } from "./api_client";

// |====== CRUD Device API ======|

// Device.jsx ใช้ดึงรายการอุปกรณ์ 1 ชุด (keyset pagination) - afterDevId = cursor จาก next_cursor
// ของชุดก่อนหน้า (ไม่ส่ง/null = ขอชุดแรกสุด) คืนกลับเป็น { items, next_cursor, has_next }
export function listDevices(siteId, afterDevId) {
  if (!siteId) {
    throw new Error("Missing parameter")
  }
  const params = new URLSearchParams();
  params.set("site_id", siteId);
  if (afterDevId) params.set("after_dev_id", afterDevId);
  const query = params.toString();
  return request(`/devices/${query ? `?${query}` : ""}`);
}

// ส่ง api ไปขอลบอุปกรณ์ตัวที่กำหนด
export function deleteDevice(devId) {
  return request(`/devices/${devId}`, { method: "DELETE" });
}

// ส่ง api ไปขอข้อมูลอุปกรณ์ตัวที่กำหนด
export function getDevice(devId) {
  return request(`/devices/${devId}`);
}

// ส่ง api ไปขอคำสั่งอุปกรณ์ที่ใช้ได้ของตัวที่กำหนด
export function getDeviceCommands(devId) {
  return request(`/devices/${devId}/commands`);
}

// (dynamic feature ขั้นที่ 5) สรุปความสามารถของอุปกรณ์จากโปรไฟล์ที่ backend ตรวจไว้ตอน call-home
// คืน { enforced, checked, probing, status, checked_at, layers, skipped_layers, hidden: [{ command, kind, reasons }] }
export function getDeviceCapability(devId) {
  return request(`/devices/${devId}/capability`);
}

// ส่ง api ไปขอประวัติคำสั่งของอุปกรณ์ที่กำหนด 1 ชุด (keyset pagination)
// afterHisId = his_id ตัวสุดท้ายของชุดก่อนหน้า (ไม่ส่ง/null = ขอชุดแรกสุด = ใหม่สุด)
// คืนกลับเป็น { items, next_cursor, has_next }
export function getDeviceHistory(devId, afterHisId) {
  const params = new URLSearchParams();
  if (afterHisId) params.set("after_his_id", afterHisId);
  const query = params.toString();
  return request(`/devices/${devId}/history${query ? `?${query}` : ""}`);
}

// ส่ง api ไปขอ CPU/RAM ล่าสุดจากของอุปกรณ์ที่กำหนด
export function getDeviceStats(devId) {
  return request(`/devices/${devId}/stats`);
}

// DeviceDetail.jsx ใช้บันทึก heartbeat ของตัวเอง + คืนรายชื่อทุกคนที่ยัง heartbeat ไม่หมดอายุแสดงบน basic_info
export function pingDevicePresence(devId) {
  return request(`/devices/${devId}/presence/ping`, { method: "POST" });
}

// หนึ่ง UUID แทนการเปิดหน้า Device Detail หนึ่งรอบ: start สร้าง log เพียงแถวเดียว
// และ heartbeat อัปเดต Last Seen ของแถวนั้นโดยไม่สร้าง log ซ้ำทุก 10 วินาที
export function startDeviceAccessSession(devId, sessionId) {
  return request(`/devices/${devId}/access-sessions`, {
    method: "POST",
    body: { session_id: sessionId },
  });
}

export function heartbeatDeviceAccessSession(devId, sessionId) {
  return request(`/devices/${devId}/access-sessions/${encodeURIComponent(sessionId)}/heartbeat`, {
    method: "POST",
  });
}

// System Management > Access Log ใช้ keyset pagination ครั้งละ 40 แถว
export function getDeviceAccessLog(devId, afterAccId) {
  const params = new URLSearchParams();
  if (afterAccId) params.set("after_acc_id", afterAccId);
  const query = params.toString();
  return request(`/devices/${devId}/access-log${query ? `?${query}` : ""}`);
}

// Read the full running configuration only when the user explicitly asks for
// it. The backend stores a sanitized snapshot in Redis for 15 minutes.
export function createRunningConfigSnapshot(devId) {
  return request(`/devices/${encodeURIComponent(devId)}/running-config-snapshots`, {
    method: "POST",
  });
}

// This reads the temporary Redis snapshot only; it never queries the device.
export function getRunningConfigSnapshot(devId, snapshotId) {
  return request(
    `/devices/${encodeURIComponent(devId)}/running-config-snapshots/${encodeURIComponent(snapshotId)}`,
  );
}

// Factory reset has vendor-specific backend semantics and must not pass through
// the generic command endpoint (Cisco/Huawei may disconnect before replying;
// Juniper additionally verifies its current root password).
export async function factoryResetDevice(devId, rootPassword = null) {
  try {
    const result = await request(`/devices/${encodeURIComponent(devId)}/factory-reset`, {
      method: "POST",
      body: rootPassword ? { root_password: rootPassword } : {},
    });
    announceDeviceStateChanged(devId);
    window.dispatchEvent(new CustomEvent("toast:success", { detail: `✓ ${result.message}` }));
    return result;
  } catch (err) {
    announceDeviceStateChanged(devId);
    throw err;
  }
}

// สิ่งที่ระบบจำไว้ว่าสั่งสร้างไปแล้ว (ตอนนี้มีแค่ NAT) - feature ไม่ใส่ = เอาทุก
// feature ของอุปกรณ์นี้มา
export function getDeviceConfigObjects(devId, feature) {
  const query = feature ? `?feature=${encodeURIComponent(feature)}` : "";
  return request(`/devices/${devId}/config-objects${query}`);
}

// (ปัญหาที่ 1 ขั้น A5) toast ความสำเร็จต้องขึ้น "ครั้งเดียวตอนจบชุด" ไม่ใช่ทุกคำสั่ง
//
// เดิม 1 action ของผู้ใช้ที่ยิง 12 คำสั่ง = toast เขียว 12 อันซ้อนกัน ซึ่งทั้งรกและ
// ทำให้ผู้ใช้เข้าใจผิดว่ามีการบันทึก 12 ครั้ง - ที่แย่กว่านั้นคือถ้าคำสั่งที่ 3 ล้มเหลว
// ผู้ใช้จะเห็น toast เขียว 2 อันของคำสั่งที่ 1-2 คู่กับ error สีแดง ซึ่งอ่านแล้วสับสน
// ว่าตกลงสำเร็จหรือไม่
//
// วิธีที่ใช้: เลื่อนการยิง toast ออกไปเล็กน้อยแล้วรีเซ็ตตัวจับเวลาทุกครั้งที่มีคำสั่ง
// ถัดไปสำเร็จ - ชุดคำสั่งที่ยิงต่อกันจึงยุบเหลือ toast เดียวที่ปลายชุด และถ้าชุดจบ
// ด้วยความล้มเหลว toast ที่ตั้งเวลาไว้จะถูก "ยกเลิกทิ้ง" ผู้ใช้เห็นแต่ error อย่างเดียว
//
// เลือกทำที่นี่แทนการไปแก้ 26 flow ให้ยิง toast เองตอนจบ เพราะแก้จุดเดียวได้ผลทั้งแอป
// และ flow ที่เขียนเพิ่มในอนาคตจะได้พฤติกรรมนี้ฟรีโดยไม่ต้องจำ
//
// 700ms มาจาก: ช่องว่างระหว่างคำสั่งในชุดคือเวลา JS ล้วนๆ บวก sleep ที่ยาวสุดใน
// โปรเจกต์ตอนนี้ (POST_INTERFACE_COMMIT_DELAY_MS = 300ms ใน InterfacesFormModal)
// ส่วนเวลาที่รอ response จากอุปกรณ์ไม่นับ เพราะตัวจับเวลาเริ่มนับหลังคำสั่งสำเร็จแล้ว
const SUCCESS_TOAST_DEBOUNCE_MS = 700;
let pendingSuccessToast = null;

function scheduleSuccessToast() {
  if (pendingSuccessToast) clearTimeout(pendingSuccessToast);
  pendingSuccessToast = setTimeout(() => {
    pendingSuccessToast = null;
    window.dispatchEvent(new CustomEvent("toast:success", { detail: "✓ Changes saved successfully" }));
  }, SUCCESS_TOAST_DEBOUNCE_MS);
}

function cancelPendingSuccessToast() {
  if (!pendingSuccessToast) return;
  clearTimeout(pendingSuccessToast);
  pendingSuccessToast = null;
}

// (ปัญหาที่ 1 ขั้น A4) คำสั่ง "เขียน" ที่ล้มเหลวกลางชุด แปลว่าคำสั่งก่อนหน้าในชุดนั้น
// อาจ apply ลงอุปกรณ์ไปแล้วบางส่วน - หน้าจอที่ผู้ใช้เห็นอยู่จึงไม่ตรงกับอุปกรณ์จริง
// อีกต่อไป และถ้าปล่อยไว้ผู้ใช้จะกดซ้ำบนสมมติฐานที่ผิด
//
// เดิม modal เรียก refetch ผ่าน onSaved() "เฉพาะตอนสำเร็จ" เท่านั้น พอ error จึงค้าง
// state เก่า - แทนที่จะไล่แก้ทั้ง 26 flow ให้เรียก refetch เองใน catch (ซึ่งต้องเพิ่ม
// prop ใหม่ให้ทุก modal และ flow ที่เขียนเพิ่มทีหลังก็ต้องจำอีก) ใช้ window event
// แบบเดียวกับ toast:success ที่โปรเจกต์ใช้อยู่แล้ว แล้วให้ hook getDeviceInformation
// เป็นคนฟัง - 32 จาก 46 ไฟล์ใน cmdGroups ดึงข้อมูลผ่าน hook ตัวนี้ทั้งหมด ที่เหลือ
// เป็น form modal ที่ list แม่ของมันใช้ hook นี้อยู่แล้ว จึงครอบคลุมทั้งแอปด้วยการ
// แก้ 2 ไฟล์
function announceDeviceStateChanged(devId) {
  window.dispatchEvent(new CustomEvent("device:state-changed", { detail: { devId } }));
}

// รวมข้อความจาก rpc-error หลายตัวใน reply เดียวให้อ่านรู้เรื่อง - ตัดตัวซ้ำออก
// (อุปกรณ์บางตัวตอบ error เดียวกันซ้ำหลายรอบใน edit-config ที่มีหลาย element)
function formatDeviceErrors(errors, fallbackMessage) {
  const messages = [...new Set((errors || []).map((e) => e?.message).filter(Boolean))];
  if (!messages.length) return fallbackMessage;
  return messages.join("; ");
}

// ส่ง api ใช้ยิงคำสั่งแก้ไข config จริง
//
// (ปัญหาที่ 1 ใน planning/transaction_review.md ขั้น A2/A5) เดิมฟังก์ชันนี้ตีความว่า
// "ไม่ throw = สำเร็จ" ซึ่งผิด เพราะ edit-config ที่ถูกอุปกรณ์ปฏิเสธด้วย rpc-error
// ตอบกลับมาเป็น HTTP 200 ปกติพร้อม {ok: false, errors: [...]} ไม่ใช่ exception
// (ต่างจาก commit ที่ล้มเหลวซึ่ง throw จริง) ผลคือ:
//   1. ชุดคำสั่งที่ยิงต่อกันวิ่งต่อไปทั้งชุดบนสมมติฐานที่ผิด
//   2. toast เขียว "เรียบร้อยแล้ว" ขึ้นทุกคำสั่งรวมทั้งตัวที่ล้มเหลว
// ตอนนี้ย้ายด่านตรวจมาไว้ที่นี่จุดเดียว แทนที่จะให้แต่ละ modal ครอบเอง (เดิมมี
// assertCommandOk อยู่ใน InterfacesFormModal แต่ถูก copy ไปใช้แค่ 5 จาก 26 จุด
// และไฟล์ใหม่ที่เขียนทีหลังก็ต้องจำว่าต้องครอบอีก ซึ่งจะลืมแน่นอน)
//
// ลำดับสำคัญ: ตรวจ ok ให้เสร็จ "ก่อน" ยิง toast ไม่งั้น toast เขียวยังขึ้นอยู่ดี
//
// allowFailure: ตั้งใจให้เป็น opt-in ที่ต้องระบุชัด ไม่ใช่ opt-out - พฤติกรรม
// "ล้มเหลวแล้วเงียบ" ควรเป็นสิ่งที่คนเขียนตั้งใจเลือก ไม่ใช่ค่า default ที่ได้มาฟรี
// ใช้กับคำสั่งเก็บกวาดท้ายชุดที่ล้มเหลวแล้วไม่กระทบผลลัพธ์หลักเท่านั้น
// (ปัญหาที่ 2 ขั้น B0) ตรวจพารามิเตอร์ของคำสั่งโดยไม่ส่งอะไรไปที่อุปกรณ์
//
// ใช้กับ flow ที่ "ลบของเดิมทิ้งก่อนแล้วค่อยสร้างใหม่" - ต้องเรียกตัวนี้ให้ผ่านก่อน
// เริ่มลบเสมอ ไม่งั้นถ้าค่าที่ผู้ใช้กรอกผิด ระบบจะลบของเดิมสำเร็จไปแล้วทั้งหมดก่อน
// จะมาโดนปฏิเสธที่ขั้นสร้าง = ของเดิมหายโดยไม่มีอะไรมาแทน
//
// backend ตรวจด้วย build_payload() ตัวเดียวกับตอนสั่งจริง จึงการันตีว่าผ่านที่นี่แล้ว
// จะผ่านตอนสร้างจริงด้วย - ไม่ใช่การเขียนกฎซ้ำอีกชุดฝั่ง frontend ซึ่งจะเพี้ยนออก
// จากกันแน่นอน (บทเรียนจาก BUG-12/13/14/15)
//
// โยน error หน้าตาเดียวกับ runDeviceCommand (มี .detail) ให้ catch block เดิมจับได้เลย
export async function validateDeviceCommand(devId, command, parameters = {}) {
  return request(`/devices/${devId}/command/${command}/validate`, {
    method: "POST",
    body: { parameters },
  });
}

export async function runDeviceCommand(devId, command, parameters = {}, { allowFailure = false } = {}) {
  let response;
  try {
    response = await request(`/devices/${devId}/command/${command}`, {
      method: "POST",
      body: { parameters },
    });
  } catch (err) {
    // HTTP error (409 session หลุด / 503 timeout / 400 validate ไม่ผ่าน ฯลฯ) -
    // ยกเลิก toast ที่คำสั่งก่อนหน้าในชุดตั้งเวลาไว้ ไม่งั้นชุดที่จบด้วยความล้มเหลว
    // จะยังขึ้นเขียวคู่กับ error
    cancelPendingSuccessToast();
    // (2026-09) Cisco NAT family (Source/Static/Port Forward): "write outcome
    // unknown" (เขียน timeout - อุปกรณ์อาจ apply ไปแล้วหรือยัง ไม่รู้แน่) หรือ
    // "session recovering" (โดน quarantine gate ปฏิเสธไปก่อนถึง wire เลย - ดู
    // backend/api/device_router.py's CISCO_NAT_QUARANTINE_COMMANDS) ต้องไม่ทำให้
    // ทุก hook ของอุปกรณ์นี้ refetch ทันที เพราะอุปกรณ์อาจยังประมวลผล edit-config
    // เดิมอยู่ หรือ session ยังไล่ reply เก่าไม่หมด - ยิง read เพิ่มตอนนี้มีแต่จะซ้ำ
    // เติม backlog ที่กลไกนี้ตั้งใจกันไว้ - เช็คจาก structured error code เท่านั้น
    // (ไม่ค้น substring ข้อความ) และมีแค่ 2 code นี้เท่านั้นที่ถูกกัน error แบบอื่น
    // (rpc-error จริง, validation, session disconnected ฯลฯ) ยัง announce ตามปกติ
    // ทุกประการ - ทั้งสอง code นี้ backend สร้างให้เฉพาะคำสั่ง Cisco NAT เท่านั้น
    // จึงไม่กระทบ Juniper/Huawei หรือฟีเจอร์อื่นเลย
    const errorCode = err?.detail && typeof err.detail === "object" ? err.detail.code : null;
    const isNatOutcomePending = errorCode === "NETCONF_WRITE_OUTCOME_UNKNOWN" || errorCode === "NETCONF_SESSION_RECOVERING";
    if (!command.startsWith("get_") && !isNatOutcomePending) announceDeviceStateChanged(devId);
    throw err;
  }

  // normalize() ฝั่ง backend คืน {ok: false, errors: [...]} ให้ทั้งคำสั่งอ่านและเขียน
  // ที่อุปกรณ์ตอบ rpc-error กลับมา (ดู vendor_translators/response_normalizer.py)
  if (!allowFailure && response?.result?.ok === false) {
    cancelPendingSuccessToast();
    if (!command.startsWith("get_")) announceDeviceStateChanged(devId);
    const message = formatDeviceErrors(response.result.errors, `Device rejected command ${command}`);
    const error = new Error(message);
    error.detail = message;
    error.deviceCommand = command;
    error.deviceErrors = response.result.errors || [];
    throw error;
  }

  if (!command.startsWith("get_")) {
    scheduleSuccessToast();
  }
  return response;
}

// Candidate: edit ทั้งชุดแล้ว commit ครั้งเดียว; Cisco running: รวม payload ที่
// combiner รองรับใน scope เดียวกัน (ปัจจุบัน Interface/DHCP หรือ NTP)
// เป็น edit-config เดียวพร้อม rollback-on-error ไม่มีการ fallback ไปยิงแยกคำสั่ง
// ทั้งชุดสำเร็จหรือถูกยกเลิก - error/toast เดินเส้นทางเดียวกับ
// runDeviceCommand ทุกประการ ฝั่งเรียกจึงจับ err.detail ได้เหมือนเดิม
export async function runDeviceTransaction(devId, commands) {
  let response;
  try {
    response = await request(`/devices/${devId}/transaction`, {
      method: "POST",
      body: { commands },
    });
  } catch (err) {
    cancelPendingSuccessToast();
    announceDeviceStateChanged(devId);
    throw err;
  }

  if (response?.result?.ok === false) {
    cancelPendingSuccessToast();
    announceDeviceStateChanged(devId);
    const message = formatDeviceErrors(response.result.errors, `Device rejected command ${response.command}`);
    const error = new Error(message);
    error.detail = message;
    error.deviceCommand = response.command;
    error.deviceErrors = response.result.errors || [];
    throw error;
  }

  scheduleSuccessToast();
  return response;
}

// ส่ง api ไปสั่งทดสอบ ping connectivity จริงจากอุปกรณ์
export function runPingTest(devId, destination, sourceInterface) {
  return request(`/devices/${devId}/ping-test`, {
    method: "POST",
    body: { destination, source_interface: sourceInterface || null },
  });
}

// Phase 9: Reset Device Identity สำหรับ Device ที่ผ่าน Token Enrollment แล้ว
export function resetDeviceIdentity(devId, forceOffline = false) {
  const query = forceOffline ? "?force_offline=true" : "";
  return request(`/devices/${devId}/reset-identity${query}`, {
    method: "POST",
  });
}
