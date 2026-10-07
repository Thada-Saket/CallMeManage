// |====== เส้นทางของ flow เพิ่มอุปกรณ์ (Token Enrollment) ======|
// ไม่มี site_id = ไม่มีเส้นทาง (คืน null) - ห้ามเปิด CLI Generator แบบไม่มี Site context

export function cliGeneratorUrl(siteId, pendingDeviceId = null) {
  if (!siteId) return null;
  let url = `/cli-generate?site_id=${encodeURIComponent(siteId)}`;
  if (pendingDeviceId) url += `&pending_device_id=${encodeURIComponent(pendingDeviceId)}`;
  return url;
}

export function devicesUrl(siteId) {
  return siteId ? `/devices?site_id=${encodeURIComponent(siteId)}` : "/sites";
}
