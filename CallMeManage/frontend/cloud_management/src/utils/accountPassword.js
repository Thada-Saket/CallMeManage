// CM-09: website account password policy - UX mirror only.
// The backend (backend/core/account_password_policy.py) is the real gate; keep both in sync.
// Not the device local-user policy in localAdmin.js: that one carries CLI limits of the devices.

export const ACCOUNT_PASSWORD_MIN_LENGTH = 8;
export const ACCOUNT_PASSWORD_MAX_LENGTH = 256;

// Count code points like Python's len(), so an emoji counts once on both sides.
const length = (password) => [...password].length;

export const ACCOUNT_PASSWORD_RULES = [
  { label: `At least ${ACCOUNT_PASSWORD_MIN_LENGTH} characters long`, test: (p) => length(p) >= ACCOUNT_PASSWORD_MIN_LENGTH },
  { label: "Contains lowercase letter (a-z)", test: (p) => /[a-z]/.test(p) },
  { label: "Contains uppercase letter (A-Z)", test: (p) => /[A-Z]/.test(p) },
  { label: "Contains number (0-9)", test: (p) => /[0-9]/.test(p) },
  { label: "Contains special character", test: (p) => /[^A-Za-z0-9]/.test(p) },
];

// Same shape PasswordPolicyHint expects: [{ label, passed }]
export function accountPasswordChecks(password) {
  const value = typeof password === "string" ? password : "";
  return ACCOUNT_PASSWORD_RULES.map((rule) => ({ label: rule.label, passed: rule.test(value) }));
}

export function isAccountPasswordValid(password) {
  if (typeof password !== "string" || length(password) > ACCOUNT_PASSWORD_MAX_LENGTH) return false;
  return ACCOUNT_PASSWORD_RULES.every((rule) => rule.test(password));
}
