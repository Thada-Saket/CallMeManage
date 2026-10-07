export function hoursToLeaseMinutes(value) {
  const raw = String(value).trim();
  if (!/^\d+(?:\.\d+)?$/.test(raw)) return null;
  const minutes = Number(raw) * 60;
  const integer = Math.round(minutes);
  return Number.isSafeInteger(integer) && integer > 0 && Math.abs(minutes - integer) < 1e-8 ? integer : null;
}

export function readDhcpLease(vendor, lease) {
  if (vendor === "juniper") {
    const raw = lease?.["maximum-lease-time"];
    if (raw === undefined || raw === null || raw === "") return {leaseSeconds: null, leaseInfinite: false};
    const seconds = Number(raw);
    return Number.isSafeInteger(seconds) && seconds > 0
      ? {leaseSeconds: seconds, leaseInfinite: false}
      : {leaseSeconds: null, leaseInfinite: false, leaseRaw: String(raw)};
  }
  if (lease && Object.hasOwn(lease, "infinite")) return {leaseSeconds: null, leaseInfinite: true};
  const value = lease?.["lease-value"];
  if (!value) return {leaseSeconds: null, leaseInfinite: false};
  const seconds = Number(value.days ?? 1) * 86400 + Number(value.hours ?? 0) * 3600 + Number(value.minutes ?? 0) * 60;
  return {leaseSeconds: seconds, leaseInfinite: false};
}

export function leaseHoursInput(pool) {
  if (pool?.leaseInfinite) return "infinite";
  if (pool?.leaseRaw) return pool.leaseRaw;
  return pool?.leaseSeconds === null || pool?.leaseSeconds === undefined ? "" : String(pool.leaseSeconds / 3600);
}

export function formatLeaseHours(pool) {
  if (pool.leaseInfinite) return "Infinite";
  if (pool.leaseRaw) return pool.leaseRaw;
  if (pool.leaseSeconds === null || pool.leaseSeconds === undefined) return "Not configured";
  const hours = pool.leaseSeconds / 3600;
  const text = String(Number(hours.toFixed(8)));
  // Show exact seconds too when decimal hours require rounding.
  return Number(text) * 3600 === pool.leaseSeconds
    ? `${text} hours` : `≈ ${text} hours (${pool.leaseSeconds}s)`;
}
