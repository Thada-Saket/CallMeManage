import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import fs from "node:fs"

// All settings come from the system config file (the same one the backend reads):
// /etc/callmemanage/callmemanage.conf, or the path in CALLMEMANAGE_CONF for development.
// Only ROOT_PATH is built into the website; everything else applies on restart.
// Nothing from this file reaches the browser bundle.
const CONFIG_FILE = process.env.CALLMEMANAGE_CONF || "/etc/callmemanage/callmemanage.conf";

function readConfig(path) {
  const values = {};
  if (!fs.existsSync(path)) return values;
  for (const line of fs.readFileSync(path, "utf8").split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || !trimmed.includes("=")) continue;
    const index = trimmed.indexOf("=");
    values[trimmed.slice(0, index).trim()] = cleanValue(trimmed.slice(index + 1));
  }
  return values;
}

// Same rules as the backend's reader (python-dotenv): "value" or 'value' loses its quotes,
// otherwise " # ..." at the end is a comment.
function cleanValue(raw) {
  const value = raw.trim();
  const quoted = value.match(/^(["'])(.*)\1$/);
  if (quoted) return quoted[2];
  return value.replace(/\s+#.*$/, "").trim();
}

// A reverse proxy written as `ProxyPass /cmm https://host:8080/cmm/` (trailing slash on one
// side only) forwards /cmm/api/x as /cmm//api/x. Static files still load, but the API proxy
// below matches the exact prefix and the page gets index.html instead of JSON. Collapse
// repeated slashes in the path before anything else looks at it.
function collapseSlashes() {
  const middleware = (req, _res, next) => {
    const [path, ...query] = req.url.split("?");
    if (path.includes("//")) req.url = [path.replace(/\/{2,}/g, "/"), ...query].join("?");
    next();
  };
  return {
    name: "callmemanage-collapse-slashes",
    configureServer: (server) => { server.middlewares.use(middleware); },
    configurePreviewServer: (server) => { server.middlewares.use(middleware); },
  };
}

// "/", "cmm", "/cmm" -> "/" or "/cmm/"
function normalizeBasePath(value) {
  const cleaned = String(value || "/").trim().replace(/^\/+|\/+$/g, "");
  return cleaned ? `/${cleaned}/` : "/";
}

// https://vite.dev/config/
export default defineConfig(() => {
  const config = readConfig(CONFIG_FILE);
  // Path the website lives under: "/" or e.g. "/cmm/" behind a reverse proxy at /cmm.
  // It is written into the build, so changing it needs a rebuild (callmemanage apply does it).
  const appBase = normalizeBasePath(config.ROOT_PATH);
  const backendPort = Number(config.BACKEND_PORT || 8000);
  const certFile = config.TLS_CERT_FILE || "../../tools/keys/cert/server.crt";
  const keyFile = config.TLS_KEY_FILE || "../../tools/keys/cert/server.key";
  // A missing certificate only turns HTTPS off (e.g. `npm run build` on a fresh checkout).
  const https = fs.existsSync(certFile) && fs.existsSync(keyFile)
    ? { cert: fs.readFileSync(certFile), key: fs.readFileSync(keyFile) }
    : undefined;

  // The browser calls <ROOT_PATH>api/... on this server; it is forwarded to the backend
  // with that prefix removed (FastAPI serves /auth/..., /bootstrap/... at its root).
  const apiPath = `${appBase}api`;
  // Host names the website answers to (IP addresses are always accepted by Vite):
  // the same sources the backend uses - SITE_URL and ALLOWED_HOSTS.
  const siteHost = config.SITE_URL ? new URL(config.SITE_URL).hostname : "";
  const allowedHosts = ["localhost", "www.callmemanage.local", "callmemanage.local", siteHost,
    ...String(config.ALLOWED_HOSTS || "").split(",")].map((host) => host.trim()).filter(Boolean);
  const apiProxy = {
    [apiPath]: {
      // backend runs HTTPS with the certificate above; secure:false accepts a
      // self-signed one for this loopback hop only
      target: `https://127.0.0.1:${backendPort}`,
      secure: false,
      // pass the real client IP (X-Forwarded-For); backend trusts it only from 127.0.0.1
      xfwd: true,
      changeOrigin: true,
      rewrite: (path) => path.slice(apiPath.length) || "/",
    },
  };

  return {
    plugins: [collapseSlashes(), react()],
    base: appBase,
    server: {
      host: true,
      proxy: apiProxy,
      allowedHosts,
      https,
    },
    build: {
      sourcemap: false,
      minify: 'esbuild'
    },
    // `vite preview` is the website server of the callmemanage-frontend service
    preview: {
      host: config.BIND_HOST || "0.0.0.0",
      port: Number(config.FRONTEND_PORT || 8080),
      strictPort: true,
      https,
      proxy: apiProxy,
      allowedHosts,
    },
  };
})
