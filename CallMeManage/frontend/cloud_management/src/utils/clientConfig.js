import { request } from "../api/api_client";

// Public settings from the server config file (GET /auth/client-config), loaded once per
// page load. Cloudflare can be switched on/off or get a new site key with only a restart.
let pending = null;

// After a restart the website answers a few seconds before the backend does; keep trying
// for about 15 s so a page opened in that window does not show an error.
const RETRY_DELAYS_MS = [500, 1000, 2000, 3000, 4000, 5000];

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// A plain-language reason for the error screen
export function clientConfigProblem(error) {
  if (error?.status === 404) {
    return "The website cannot find its server API (404). The reverse proxy or ROOT_PATH may be set up wrong";
  }
  if (error?.status >= 500) {
    return `The server is starting or stopped (${error.status}). Reload the page in a moment`;
  }
  return "The server is not reachable. Reload the page to try again";
}

async function load() {
  for (let attempt = 0; ; attempt += 1) {
    try {
      const data = await request("/auth/client-config", { auth: false });
      if (typeof data?.turnstile_enabled !== "boolean") {
        // a web page instead of JSON: the request did not reach the backend
        throw Object.assign(new Error("not the API"), { status: 404 });
      }
      return {
        turnstileEnabled: data.turnstile_enabled,
        turnstileSiteKey: data.turnstile_site_key || "",
      };
    } catch (caught) {
      // an HTML page where JSON was expected also means the request missed the backend
      const error = caught instanceof SyntaxError ? Object.assign(caught, { status: 404 }) : caught;
      // 404 will not fix itself; anything else (502, network) may be a restart in progress
      if (error?.status === 404 || attempt >= RETRY_DELAYS_MS.length) throw error;
      await wait(RETRY_DELAYS_MS[attempt]);
    }
  }
}

export function getClientConfig() {
  if (!pending) {
    pending = load().catch((error) => {
      pending = null; // let the next caller try again
      throw error;
    });
  }
  return pending;
}
