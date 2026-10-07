import { request } from "../api/api_client";

// Public settings from the server config file (GET /auth/client-config), loaded once per
// page load. Cloudflare can be switched on/off or get a new site key with only a restart.
let pending = null;

export function getClientConfig() {
  if (!pending) {
    pending = request("/auth/client-config", { auth: false })
      .then((data) => ({
        turnstileEnabled: data?.turnstile_enabled === true,
        turnstileSiteKey: data?.turnstile_site_key || "",
      }))
      .catch((error) => {
        pending = null; // let the next caller try again
        throw error;
      });
  }
  return pending;
}
