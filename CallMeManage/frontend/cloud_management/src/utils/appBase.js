// Root path of the website from ROOT_PATH in callmemanage.conf: "/" locally, "/cmm/" behind
// a reverse proxy at /cmm. Vite fixes it at build time as import.meta.env.BASE_URL.
export const APP_BASE_PATH = import.meta.env.BASE_URL;

export function appUrl(path = "") {
  return `${APP_BASE_PATH}${String(path).replace(/^\/+/, "")}`;
}
