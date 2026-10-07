import { useEffect, useRef, useState } from "react";
import DismissibleError from "./DismissibleError";
import { clearSiteAccessToken } from "../api/api_client";
import { verifySiteAccess } from "../api/api_site_access";
import { loadTurnstileScript } from "../utils/turnstile";
import { clientConfigProblem, getClientConfig } from "../utils/clientConfig";
import { siteAccessValid } from "../utils/siteAccess";

export default function SiteAccessGate({ children }) {
  // null = still asking the server whether Cloudflare is switched on
  const [config, setConfig] = useState(null);
  // A stored token counts only while it is still valid for a while: an expired one from
  // yesterday's tab must bring the gate back now, not after the user submits a form.
  const [verified, setVerified] = useState(() => {
    if (siteAccessValid()) return true;
    clearSiteAccessToken();
    return false;
  });
  const [error, setError] = useState("");
  const [checking, setChecking] = useState(false);
  const [canRetry, setCanRetry] = useState(false);
  const containerRef = useRef(null);
  const widgetRef = useRef(null);
  const checkingRef = useRef(false);

  useEffect(() => {
    function requireVerification() {
      setVerified(false);
    }
    window.addEventListener("site-access:required", requireVerification);
    return () => window.removeEventListener("site-access:required", requireVerification);
  }, []);

  useEffect(() => {
    let active = true;
    getClientConfig()
      .then((value) => { if (active) setConfig(value); })
      .catch((err) => { if (active) setError(clientConfigProblem(err)); });
    return () => { active = false; };
  }, []);

  useEffect(() => {
    if (verified || !config?.turnstileEnabled) return undefined;
    let active = true;
    const sitekey = config.turnstileSiteKey;

    async function renderWidget() {
      if (!sitekey) {
        setError("Turnstile site key is not configured for this environment");
        return;
      }
      try {
        await loadTurnstileScript();
        if (!active || !containerRef.current) return;
        widgetRef.current = window.turnstile.render(containerRef.current, {
          sitekey,
          theme: "dark",
          size: "flexible",
          appearance: "always",
          action: "site_access",
          callback: async (token) => {
            if (!active || checkingRef.current) return;
            checkingRef.current = true;
            setChecking(true);
            setCanRetry(false);
            setError("");
            try {
              await verifySiteAccess(token);
              if (active) setVerified(true);
            } catch (err) {
              if (!active) return;
              setError(err.detail || "Bot verification failed. Try again");
              // Do not reset here. The always-pass test widget immediately emits
              // another token after reset, which otherwise creates a request loop
              // whenever the backend rejects a mismatched key or configuration.
              setCanRetry(true);
            } finally {
              checkingRef.current = false;
              if (active) setChecking(false);
            }
          },
          "expired-callback": () => {
            if (active) {
              setError("Verification expired. Complete the check again");
              setCanRetry(true);
            }
          },
          "error-callback": () => {
            if (active) {
              setError("Bot verification could not be loaded. Try again");
              setCanRetry(true);
            }
          },
        });
      } catch {
        if (active) setError("Bot verification is temporarily unavailable");
      }
    }

    renderWidget();
    return () => {
      active = false;
      if (window.turnstile && widgetRef.current != null) {
        window.turnstile.remove(widgetRef.current);
      }
      widgetRef.current = null;
    };
  }, [verified, config]);

  function retryVerification() {
    setError("");
    setCanRetry(false);
    checkingRef.current = false;
    if (window.turnstile && widgetRef.current != null) {
      window.turnstile.reset(widgetRef.current);
    }
  }

  // Cloudflare switched off on the server: no human check, straight to the website
  if (verified || config?.turnstileEnabled === false) return children;

  return (
    <main className="site-access-screen">
      <section className="site-access-card" aria-labelledby="site-access-title">
        <span className="brand-mark">CM</span>
        <h1 id="site-access-title">CallMe Manage</h1>
        <p>Confirm that you are human before entering the website.</p>
        {error && <DismissibleError message={error} onDismiss={() => setError("")} />}
        <div ref={containerRef} className="site-access-widget" aria-label="Human verification" />
        {checking && <span className="site-access-status">Verifying...</span>}
        {canRetry && !checking && (
          <button type="button" className="btn btn-ghost" onClick={retryVerification}>
            Try Again
          </button>
        )}
      </section>
    </main>
  );
}
