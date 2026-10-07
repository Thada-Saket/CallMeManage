import { useEffect, useRef } from "react";
import { loadTurnstileScript } from "../utils/turnstile";
import { getClientConfig } from "../utils/clientConfig";

/**
 * Single-use Turnstile token for one protected action (e.g. login).
 * onToken receives a fresh token, or "" when the token expired or failed so
 * the owner can disable submit. Bump resetSignal after every attempt: a token
 * can be redeemed only once, so the widget must issue a new one.
 * The widget stays hidden unless Cloudflare needs the user to interact.
 * Render it only when the server has Cloudflare switched on (getClientConfig).
 */
export default function TurnstileWidget({ action, onToken, onError, resetSignal = 0 }) {
  const containerRef = useRef(null);
  const widgetRef = useRef(null);
  const callbacksRef = useRef({ onToken, onError });
  useEffect(() => {
    callbacksRef.current = { onToken, onError };
  });

  useEffect(() => {
    let active = true;

    async function renderWidget() {
      let sitekey = "";
      try {
        sitekey = (await getClientConfig()).turnstileSiteKey;
      } catch {
        // reported below as "not configured"
      }
      if (!active) return;
      if (!sitekey) {
        callbacksRef.current.onError?.("Turnstile site key is not configured for this environment");
        return;
      }
      try {
        await loadTurnstileScript();
        if (!active || !containerRef.current) return;
        widgetRef.current = window.turnstile.render(containerRef.current, {
          sitekey,
          action,
          theme: "dark",
          size: "flexible",
          appearance: "interaction-only",
          callback: (token) => {
            if (active) callbacksRef.current.onToken(token);
          },
          "expired-callback": () => {
            if (active) callbacksRef.current.onToken("");
          },
          "error-callback": () => {
            if (!active) return;
            callbacksRef.current.onToken("");
            callbacksRef.current.onError?.("Bot verification could not be loaded. Try again");
          },
        });
      } catch {
        if (active) callbacksRef.current.onError?.("Bot verification is temporarily unavailable");
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
  }, [action]);

  useEffect(() => {
    if (resetSignal === 0 || !window.turnstile || widgetRef.current == null) return;
    callbacksRef.current.onToken("");
    window.turnstile.reset(widgetRef.current);
  }, [resetSignal]);

  return <div ref={containerRef} className="turnstile-inline" aria-label="Human verification" />;
}
