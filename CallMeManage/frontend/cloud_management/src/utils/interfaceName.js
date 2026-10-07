// |====== Split interface name and its number ======|

// ใช้สำหรับแยกชื่อ Interface เป็นชนิดและตัวเลข
export function splitInterfaceName(fullName) {
  const match = /^([A-Za-z-]+)(.*)$/.exec(fullName.trim());
  if (!match) return { interfaceType: fullName.trim(), interfaceId: "" };
  return { interfaceType: match[1], interfaceId: match[2] };
}
