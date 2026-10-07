import {formatDate} from "./formatDate.js";

function junosTimestamp(text) {
  const match = text.match(/^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(?:\.\d+)?(?:\s+([A-Za-z]+|[+-]\d{2}:?\d{0,2}))?/);
  if (!match) return "";
  const zones = {ICT: "+07:00", UTC: "Z", GMT: "Z"};
  let zone = zones[(match[3] || "").toUpperCase()] || match[3] || "";
  if (/^[+-]\d{2}$/.test(zone)) zone += ":00";
  else if (/^[+-]\d{4}$/.test(zone)) zone = zone.slice(0, 3) + ":" + zone.slice(3);
  // Unknown abbreviations are not portable in Date.parse; browser-local time
  // is a safer fallback than returning a detailed device string.
  if (/^[A-Za-z]+$/.test(zone)) zone = "";
  return `${match[1]}T${match[2]}${zone}`;
}

function roundedElapsed(text) {
  const match = text.match(/\(([^()]*)\s+ago\)\s*$/i);
  if (!match) return "";
  const value = match[1];
  const weeks = Number(value.match(/(\d+)w/i)?.[1] || 0);
  const days = Number(value.match(/(\d+)d/i)?.[1] || 0);
  const clock = value.match(/(\d{1,2}):(\d{2})(?::(\d{2}))?/);
  const hours = Number(clock?.[1] || 0);
  const minutes = Number(clock?.[2] || 0);
  const seconds = weeks * 604800 + days * 86400 + hours * 3600 + minutes * 60 + Number(clock?.[3] || 0);
  if (seconds < 60) return "current";
  if (seconds < 3600) {
    const count = Math.floor(seconds / 60);
    return `${count} minute${count === 1 ? "" : "s"} ago`;
  }
  if (seconds < 86400) {
    const count = Math.floor(seconds / 3600);
    return `${count} hour${count === 1 ? "" : "s"} ago`;
  }
  return "";
}

export function formatInterfaceLastChange(value, vendor) {
  if (vendor !== "juniper") return formatDate(value);
  const text = typeof value === "string" ? value.trim() : "";
  if (!text) return "-";

  // Convert the Junos timestamp to the same rounded formatter Cisco uses.
  const timestamp = junosTimestamp(text);
  const formatted = timestamp ? formatDate(timestamp) : "-";
  if (formatted !== "-") return formatted;
  return roundedElapsed(text) || text;
}
