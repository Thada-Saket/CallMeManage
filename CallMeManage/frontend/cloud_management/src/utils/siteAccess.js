import { clearSiteAccessToken, getSiteAccessToken } from "../api/api_client";

// The site-access token (from passing Cloudflare on the gate) lives 8 hours. The page must
// notice an old one BEFORE the user types a password or finishes a sign-up; otherwise the
// server rejects the submit and the gate takes the page away with everything typed.
// Reading exp/iat here only decides when to show the gate - the server still verifies.
const RENEW_BEFORE_SECONDS = 15 * 60;
// Same window as FIRST_LOGIN_GRACE_SECONDS in backend/turnstile_service.py, a little shorter
// so the page never relies on a grace the server has just ended.
const FIRST_LOGIN_GRACE_SECONDS = 9 * 60;
const FIRST_LOGIN_USED_KEY = "site_access_first_login_used";

function tokenPayload(token) {
  try {
    const part = token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
    return JSON.parse(atob(part.padEnd(Math.ceil(part.length / 4) * 4, "=")));
  } catch {
    return null;
  }
}

function nowSeconds() {
  return Date.now() / 1000;
}

// true while the stored token has more than marginSeconds left
export function siteAccessValid(marginSeconds = RENEW_BEFORE_SECONDS) {
  const token = getSiteAccessToken();
  const payload = token ? tokenPayload(token) : null;
  return Boolean(payload && typeof payload.exp === "number" && payload.exp - nowSeconds() > marginSeconds);
}

// Sends the user to the gate now when the token is missing or about to run out.
// Returns false when it did. Call only when Cloudflare is switched on.
export function requireFreshSiteAccess(marginSeconds = RENEW_BEFORE_SECONDS) {
  if (siteAccessValid(marginSeconds)) return true;
  clearSiteAccessToken();
  window.dispatchEvent(new Event("site-access:required"));
  return false;
}

// The first sign-in shortly after the gate may skip the second Cloudflare check: the server
// accepts the gate's token once for that (see require_login_turnstile).
export function firstLoginGraceAvailable() {
  const payload = tokenPayload(getSiteAccessToken() || "");
  if (!payload || typeof payload.iat !== "number" || !payload.jti) return false;
  if (sessionStorage.getItem(FIRST_LOGIN_USED_KEY) === payload.jti) return false;
  return nowSeconds() - payload.iat < FIRST_LOGIN_GRACE_SECONDS;
}

export function markFirstLoginGraceUsed() {
  const payload = tokenPayload(getSiteAccessToken() || "");
  if (payload?.jti) sessionStorage.setItem(FIRST_LOGIN_USED_KEY, payload.jti);
}
