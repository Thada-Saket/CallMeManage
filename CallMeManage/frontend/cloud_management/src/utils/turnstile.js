// Loads Cloudflare's Turnstile script once, shared by the site gate and login.
const TURNSTILE_SCRIPT_ID = "cloudflare-turnstile";

export function loadTurnstileScript() {
  if (window.turnstile) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const current = document.getElementById(TURNSTILE_SCRIPT_ID);
    if (current) {
      current.addEventListener("load", resolve, { once: true });
      current.addEventListener("error", reject, { once: true });
      return;
    }
    const script = document.createElement("script");
    script.id = TURNSTILE_SCRIPT_ID;
    script.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
    script.async = true;
    script.defer = true;
    script.onload = resolve;
    script.onerror = reject;
    document.head.appendChild(script);
  });
}
