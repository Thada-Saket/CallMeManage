// Shared by the Sign Up and password-reset flows.

export function maskEmail(value) {
  const [local = "", domain = ""] = value.split("@");
  if (!domain) return value;
  const visible = local.slice(0, Math.min(2, local.length));
  return `${visible}${"*".repeat(Math.max(2, local.length - visible.length))}@${domain}`;
}

// Server responses give lifetimes in seconds; keep absolute deadlines so the
// countdown stays correct even if a timer tick is delayed.
export function deadlineFrom(seconds) {
  return Date.now() + seconds * 1000;
}

export function secondsLeft(deadline, now) {
  return deadline ? Math.max(0, Math.ceil((deadline - now) / 1000)) : 0;
}

export function formatClock(totalSeconds) {
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = String(totalSeconds % 60).padStart(2, "0");
  return `${minutes}:${seconds}`;
}
