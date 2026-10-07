import DismissibleError from "../components/DismissibleError";
import TurnstileWidget from "../components/TurnstileWidget";
import AuthNotice from "../components/AuthNotice";
import PasswordInput from "../components/PasswordInput";
import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import {
  startEmailRegistration,
  verifyEmailRegistration,
  resendEmailRegistration,
  cancelRegistration,
  startGoogleOAuthRegistration,
  completeGoogleOAuthRegistration,
  getRegistrationStatus,
} from "../api/api_auth";
import { deadlineFrom, formatClock, maskEmail, secondsLeft } from "../utils/countdown";
import PasswordResetFlow from "../components/PasswordResetFlow";
import { getClientConfig } from "../utils/clientConfig";
import { firstLoginGraceAvailable, markFirstLoginGraceUsed, requireFreshSiteAccess } from "../utils/siteAccess";
import { PasswordPolicyHint } from "../components/FieldHelp";
import {
  ACCOUNT_PASSWORD_MAX_LENGTH,
  ACCOUNT_PASSWORD_MIN_LENGTH,
  accountPasswordChecks,
  isAccountPasswordValid,
} from "../utils/accountPassword";

// CM-12: fixed text, same as the backend's 503 detail
const SIGNUP_UNAVAILABLE = "Sign up is temporarily unavailable";
const isSignupClosed = (err) => err?.status === 503 && err?.detail === SIGNUP_UNAVAILABLE;

export default function Login() {
  const { login, register } = useAuth();
  const navigate = useNavigate();

  const [isRegistering, setIsRegistering] = useState(false);
  // "loading" | "enabled" | "disabled" - only gates Sign Up; Sign In never waits for it
  const [signupStatus, setSignupStatus] = useState("loading");
  // Google button only when the backend has Google OAuth configured
  const [googleEnabled, setGoogleEnabled] = useState(false);
  const [registerStep, setRegisterStep] = useState("method");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [email, setEmail] = useState("");
  const [otp, setOtp] = useState("");
  const [challengeId, setChallengeId] = useState("");
  const [registrationToken, setRegistrationToken] = useState("");
  const [verifiedEmail, setVerifiedEmail] = useState("");
  const [registrationProvider, setRegistrationProvider] = useState("");
  const [otpExpiresAt, setOtpExpiresAt] = useState(0);
  const [flowExpiresAt, setFlowExpiresAt] = useState(0);
  const [resendAvailableAt, setResendAvailableAt] = useState(0);
  const [ticketExpiresAt, setTicketExpiresAt] = useState(0);
  const [now, setNow] = useState(() => Date.now());
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  // Prominent notice on the Sign In form after the page switched to it.
  const [authNotice, setAuthNotice] = useState(null);
  const passwordInputRef = useRef(null);
  // Sign Up only - Sign In never checks composition, so older passwords still log in
  const passwordChecks = accountPasswordChecks(password);
  const passwordValid = isAccountPasswordValid(password);
  const passwordsMismatch = confirmPassword !== "" && password !== confirmPassword;
  const usernameInputRef = useRef(null);
  const [isResetting, setIsResetting] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [resending, setResending] = useState(false);
  const [loginTurnstileToken, setLoginTurnstileToken] = useState("");
  const [loginTurnstileReset, setLoginTurnstileReset] = useState(0);
  // null until the server says whether Cloudflare is on; false = sign in without a token
  const [turnstileEnabled, setTurnstileEnabled] = useState(null);
  // The first sign-in soon after passing the gate needs no second Cloudflare check
  const [firstLoginGrace, setFirstLoginGrace] = useState(() => firstLoginGraceAvailable());
  const loginNeedsToken = turnstileEnabled !== false && !firstLoginGrace;

  useEffect(() => {
    let active = true;
    getClientConfig()
      .then((config) => { if (active) setTurnstileEnabled(config.turnstileEnabled); })
      .catch(() => { if (active) setTurnstileEnabled(true); });
    return () => { active = false; };
  }, []);

  // An old gate token must bring the gate back before anything is typed - when the page
  // opens and whenever the user comes back to this tab (e.g. from reading the email code).
  useEffect(() => {
    if (!turnstileEnabled) return undefined;
    function recheck() {
      if (document.visibilityState === "hidden") return;
      if (requireFreshSiteAccess()) setFirstLoginGrace(firstLoginGraceAvailable());
    }
    recheck();
    window.addEventListener("focus", recheck);
    document.addEventListener("visibilitychange", recheck);
    return () => {
      window.removeEventListener("focus", recheck);
      document.removeEventListener("visibilitychange", recheck);
    };
  }, [turnstileEnabled]);

  function resetRegistrationFlow() {
    setRegisterStep("method");
    setEmail("");
    setOtp("");
    setChallengeId("");
    setRegistrationToken("");
    setVerifiedEmail("");
    setRegistrationProvider("");
    setOtpExpiresAt(0);
    setFlowExpiresAt(0);
    setResendAvailableAt(0);
    setTicketExpiresAt(0);
    setNotice("");
    setConfirmPassword("");
  }

  function restartRegistration(message) {
    resetRegistrationFlow();
    setError(message);
  }

  // Best-effort: the server also expires these on its own, so a failed
  // cancel never blocks the user from leaving the flow.
  function releasePendingRegistration() {
    if (!challengeId && !registrationToken) return;
    cancelRegistration({ challengeId, registrationToken }).catch(() => {});
  }

  // Switch to Sign In and put the address in the login field (login accepts
  // email), so the user only has to type the password.
  function showSignInNotice(notice, knownEmail = "") {
    setIsRegistering(false);
    setIsResetting(false);
    setError("");
    if (knownEmail) setUsername(knownEmail);
    setPassword("");
    setAuthNotice({ ...notice, key: Date.now() });
  }

  // The server only says this after the user proved they own the address.
  function showAccountExists(knownEmail = "") {
    resetRegistrationFlow();
    showSignInNotice(
      {
        tone: "warning",
        title: "This email is already in use",
        text: "Sign in with your existing account below. Forgot the password? Use \"Forgot password?\" under the Sign In button.",
      },
      knownEmail,
    );
  }

  // HTTP 410 means the server has dropped this registration: start over.
  // HTTP 409 means the address already has an account.
  function handleRegistrationFailure(err, fallback) {
    if (isSignupClosed(err)) {
      closeSignup();
      return;
    }
    if (err.status === 409) {
      showAccountExists((verifiedEmail || email).trim());
      return;
    }
    if (err.status === 410) {
      restartRegistration(err.detail || fallback);
      return;
    }
    setError(err.detail || fallback);
  }

  function applyChallengeTimings(result) {
    setOtpExpiresAt(deadlineFrom(result.expires_in));
    setFlowExpiresAt(deadlineFrom(result.flow_expires_in));
    setResendAvailableAt(deadlineFrom(result.resend_available_in));
    setNow(Date.now());
  }

  function acceptVerifiedRegistration(result, provider) {
    setRegistrationToken(result.registration_token);
    setVerifiedEmail(result.email);
    setRegistrationProvider(provider);
    setTicketExpiresAt(deadlineFrom(result.expires_in));
    setChallengeId("");
    setNow(Date.now());
    setRegisterStep("account");
  }

  // The backend turned sign-up off (status check, 503 mid-flow or Google callback):
  // drop the flow, release what the server still holds and go back to Sign In. No retry.
  function closeSignup() {
    releasePendingRegistration();
    resetRegistrationFlow();
    setSignupStatus("disabled");
    setIsRegistering(false);
    setSubmitting(false);
    setError(SIGNUP_UNAVAILABLE);
  }

  function handleModeChange(nextIsRegistering) {
    if (nextIsRegistering && signupStatus !== "enabled") return;
    releasePendingRegistration();
    resetRegistrationFlow();
    setIsRegistering(nextIsRegistering);
    setIsResetting(false);
    setError("");
    setAuthNotice(null);
  }

  function openPasswordReset() {
    setError("");
    setAuthNotice(null);
    setPassword("");
    setIsResetting(true);
  }

  // Back to Sign In after a reset; the new password must be typed fresh.
  function closePasswordReset(changedEmail = "") {
    if (!changedEmail) {
      setIsResetting(false);
      setPassword("");
      return;
    }
    showSignInNotice(
      { tone: "success", title: "Password changed", text: "Sign in with your new password. Other devices were signed out." },
      changedEmail,
    );
  }

  // Move the cursor to the field the user has to fill next.
  useEffect(() => {
    if (!authNotice) return;
    (username ? passwordInputRef : usernameInputRef).current?.focus();
    // Only when a new notice appears, not on every keystroke.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [authNotice]);

  const timedStep = isRegistering && (registerStep === "otp" || registerStep === "account");
  useEffect(() => {
    if (!timedStep) return undefined;
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [timedStep]);

  const activeDeadline = !isRegistering ? 0 : registerStep === "otp" ? flowExpiresAt : registerStep === "account" ? ticketExpiresAt : 0;
  useEffect(() => {
    if (activeDeadline && now >= activeDeadline) {
      restartRegistration("Verification time ran out. Please start again");
    }
  }, [activeDeadline, now]);

  // Ask once; any failure keeps Sign Up closed (fail closed) while Sign In stays usable.
  useEffect(() => {
    let active = true;
    getRegistrationStatus()
      .then(({ enabled, googleEnabled: google }) => {
        if (!active) return;
        setGoogleEnabled(google);
        setSignupStatus((current) => (current === "disabled" ? current : enabled ? "enabled" : "disabled"));
      })
      .catch(() => {
        if (active) setSignupStatus("disabled");
      });
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    const hash = window.location.hash.startsWith("#") ? window.location.hash.slice(1) : "";
    const params = new URLSearchParams(hash);
    const resultCode = params.get("google_result");
    const googleError = params.get("google_error");
    if (!resultCode && !googleError) return undefined;

    window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}`);
    if (googleError === "account_exists") {
      showAccountExists();
      return undefined;
    }
    if (googleError === "signup_disabled") {
      // never call the complete endpoint; stay on Sign In
      setSignupStatus("disabled");
      setError(SIGNUP_UNAVAILABLE);
      return undefined;
    }
    setIsRegistering(true);
    setRegisterStep("method");
    if (googleError) {
      const messages = {
        invalid_state: "The Google sign-up session expired. Please try again",
        unavailable: "Google Sign Up is temporarily unavailable",
        rejected: "Google could not verify this account",
        cancelled: "Google sign-up was cancelled",
        rate_limited: "Too many failed Google sign-up attempts. Try again later",
      };
      setError(messages[googleError] || "Google registration failed");
      return undefined;
    }

    let active = true;
    setSubmitting(true);
    completeGoogleOAuthRegistration(resultCode)
      .then((result) => {
        if (active) acceptVerifiedRegistration(result, "google");
      })
      .catch((err) => {
        if (!active) return;
        if (isSignupClosed(err)) {
          // nothing is pending yet at this point, so just leave Sign Up
          setSignupStatus("disabled");
          setIsRegistering(false);
          setError(SIGNUP_UNAVAILABLE);
        } else if (err.status === 409) showAccountExists();
        else setError(err.detail || "Google registration failed");
      })
      .finally(() => {
        if (active) setSubmitting(false);
      });
    return () => {
      active = false;
    };
  }, []);

  async function handleGoogleStart() {
    setError("");
    setSubmitting(true);
    try {
      const result = await startGoogleOAuthRegistration();
      window.location.assign(result.authorization_url);
    } catch (err) {
      setSubmitting(false);
      if (isSignupClosed(err)) closeSignup();
      else setError(err.detail || "Google Sign Up is temporarily unavailable");
    }
  }

  async function handleLogin(event) {
    event.preventDefault();
    // a gate token that ran out while the form was open: back to the gate before the server says so
    if (turnstileEnabled && !requireFreshSiteAccess(60)) return;
    if (loginNeedsToken && !loginTurnstileToken) return;
    const usesGrace = turnstileEnabled !== false && firstLoginGrace;
    setError("");
    setSubmitting(true);
    try {
      await login(username.trim(), password, usesGrace ? "" : loginTurnstileToken);
      navigate("/sites", { replace: true });
    } catch (err) {
      const needsCheck = err.status === 400 && String(err.detail || "").startsWith("Complete the bot verification");
      setError(usesGrace && needsCheck
        ? "Complete the check below, then sign in again"
        : err.detail || "Failed to sign in");
      // The token was spent on this attempt (Cloudflare redeems it once).
      if (!usesGrace) setLoginTurnstileReset((count) => count + 1);
    } finally {
      if (usesGrace) {
        // one attempt per gate check: from now on each attempt needs its own check
        markFirstLoginGraceUsed();
        setFirstLoginGrace(false);
      }
      setSubmitting(false);
    }
  }

  async function handleEmailStart(event) {
    event.preventDefault();
    setError("");
    setSubmitting(true);
    try {
      const result = await startEmailRegistration(email.trim());
      setChallengeId(result.challenge_id);
      applyChallengeTimings(result);
      setOtp("");
      setNotice("");
      setRegisterStep("otp");
    } catch (err) {
      if (isSignupClosed(err)) closeSignup();
      else setError(err.detail || "Could not send the verification code");
    } finally {
      setSubmitting(false);
    }
  }

  async function handleOtpVerify(event) {
    event.preventDefault();
    setError("");
    setSubmitting(true);
    try {
      const result = await verifyEmailRegistration(challengeId, otp);
      acceptVerifiedRegistration(result, "email");
    } catch (err) {
      handleRegistrationFailure(err, "Could not verify the code");
    } finally {
      setSubmitting(false);
    }
  }

  async function handleResendOtp() {
    setError("");
    setNotice("");
    setResending(true);
    try {
      const result = await resendEmailRegistration(challengeId);
      applyChallengeTimings(result);
      setOtp("");
      setNotice("A new code was sent. Earlier codes no longer work.");
    } catch (err) {
      handleRegistrationFailure(err, "Could not send a new code");
    } finally {
      setResending(false);
    }
  }

  function handleCancelRegistration() {
    releasePendingRegistration();
    resetRegistrationFlow();
    setError("");
  }

  function handleUseAnotherAccount() {
    const provider = registrationProvider;
    handleCancelRegistration();
    if (provider === "google") handleGoogleStart();
  }

  async function handleRegistrationComplete(event) {
    event.preventDefault();
    setError("");
    // UX only - the backend enforces the same account password policy (CM-09)
    if (!isAccountPasswordValid(password)) {
      setError("Password does not meet all requirements");
      return;
    }
    if (password !== confirmPassword) {
      setError("Passwords do not match");
      return;
    }
    setSubmitting(true);
    try {
      await register(username.trim(), password, registrationToken);
      navigate("/sites", { replace: true });
    } catch (err) {
      handleRegistrationFailure(err, "Failed to sign up");
    } finally {
      setSubmitting(false);
    }
  }

  function renderRegistrationStep() {
    if (registerStep === "method") {
      return (
        <>
          {googleEnabled && (
            <>
              <button
                type="button"
                className="btn btn-ghost btn-block google-signup-button"
                onClick={handleGoogleStart}
                disabled={submitting}
              >
                {submitting ? "Connecting to Google..." : "Continue with Google"}
              </button>
              <div className="auth-divider"><span>or use your email</span></div>
            </>
          )}
          <form onSubmit={handleEmailStart}>
            <div className="field">
              <label htmlFor="registration-email">Email</label>
              <input
                id="registration-email"
                type="email"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                autoComplete="email"
                autoFocus
                required
              />
            </div>
            <button type="submit" className="btn btn-primary btn-block" disabled={submitting}>
              {submitting ? "Sending code..." : "Continue with Email"}
            </button>
          </form>
        </>
      );
    }

    if (registerStep === "otp") {
      const otpSecondsLeft = secondsLeft(otpExpiresAt, now);
      const resendSecondsLeft = secondsLeft(resendAvailableAt, now);
      const codeExpired = otpSecondsLeft === 0;
      return (
        <form onSubmit={handleOtpVerify}>
          <p className="registration-step-copy">
            We sent an email to <strong>{maskEmail(email)}</strong>. Enter the 6-digit code from it to continue.
          </p>
          {notice && <p className="registration-notice" role="status">{notice}</p>}
          <div className="field">
            <label htmlFor="registration-otp">Verification Code</label>
            <input
              id="registration-otp"
              className="otp-input"
              type="text"
              inputMode="numeric"
              autoComplete="one-time-code"
              pattern="[0-9]{6}"
              maxLength={6}
              value={otp}
              onChange={(event) => setOtp(event.target.value.replace(/\D/g, "").slice(0, 6))}
              autoFocus
              required
            />
          </div>
          <p className={`registration-timer${codeExpired ? " is-expired" : ""}`}>
            {codeExpired ? "This code has expired. Request a new code." : `Code expires in ${formatClock(otpSecondsLeft)}`}
          </p>
          <button type="submit" className="btn btn-primary btn-block" disabled={submitting || codeExpired || otp.length !== 6}>
            {submitting ? "Verifying..." : "Verify Email"}
          </button>
          <div className="registration-actions">
            <button
              type="button"
              className="link-button"
              onClick={handleResendOtp}
              disabled={resending || submitting || resendSecondsLeft > 0}
            >
              {resending
                ? "Sending..."
                : resendSecondsLeft > 0
                  ? `Resend code in ${formatClock(resendSecondsLeft)}`
                  : "Resend code"}
            </button>
            <button type="button" className="link-button" onClick={handleCancelRegistration} disabled={submitting}>
              Cancel
            </button>
          </div>
        </form>
      );
    }

    return (
      <form onSubmit={handleRegistrationComplete}>
        <div className="verified-email" title={verifiedEmail}>
          <span aria-hidden="true">✓</span> {verifiedEmail}
        </div>
        <div className="field">
          <label htmlFor="registration-username">Username</label>
          <input
            id="registration-username"
            type="text"
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            autoComplete="username"
            minLength={5}
            maxLength={32}
            autoFocus
            required
          />
        </div>
        <div className="field">
          <div className="field-label-with-hint">
            <label htmlFor="registration-password">Password</label>
            <PasswordPolicyHint checks={passwordChecks} invalid={password !== "" && !passwordValid} />
          </div>
          <input
            id="registration-password"
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            autoComplete="new-password"
            minLength={ACCOUNT_PASSWORD_MIN_LENGTH}
            maxLength={ACCOUNT_PASSWORD_MAX_LENGTH}
            aria-invalid={password !== "" && !passwordValid}
            required
          />
        </div>
        <div className="field">
          <label htmlFor="registration-confirm-password">Confirm Password</label>
          <input
            id="registration-confirm-password"
            type="password"
            value={confirmPassword}
            onChange={(event) => setConfirmPassword(event.target.value)}
            autoComplete="new-password"
            minLength={ACCOUNT_PASSWORD_MIN_LENGTH}
            maxLength={ACCOUNT_PASSWORD_MAX_LENGTH}
            aria-invalid={passwordsMismatch}
            required
          />
          {passwordsMismatch && <p className="field-note-error" role="alert">Passwords do not match</p>}
        </div>
        <button type="submit" className="btn btn-primary btn-block" disabled={submitting || !passwordValid || password !== confirmPassword}>
          {submitting ? "Creating account..." : "Create Account"}
        </button>
        <p className="registration-timer registration-timer-footer">
          Finish within {formatClock(secondsLeft(ticketExpiresAt, now))}
        </p>
        <button type="button" className="link-button registration-back" onClick={handleUseAnotherAccount} disabled={submitting}>
          {registrationProvider === "google" ? "Use another Google account" : "Use another email"}
        </button>
      </form>
    );
  }

  return (
    <div className="login-screen">
      <div className="login-card">
        <div className="login-brand">
          <span className="brand-mark">CMM</span>
          <h1>CallMeManage</h1>
          <p>
            {isResetting
              ? "Reset your password"
              : isRegistering
                ? "Create your verified account"
                : "Sign in to manage your devices"}
          </p>
        </div>

        {!isResetting && (
          <div className="login-mode-switch">
            <div className="segmented-control">
              <input type="radio" id="mode-login" name="login-mode" checked={!isRegistering} onChange={() => handleModeChange(false)} />
              <label htmlFor="mode-login">Sign In</label>
              <input
                type="radio"
                id="mode-register"
                name="login-mode"
                checked={isRegistering}
                disabled={signupStatus !== "enabled"}
                onChange={() => handleModeChange(true)}
              />
              <label htmlFor="mode-register" title={signupStatus === "disabled" ? SIGNUP_UNAVAILABLE : undefined}>Sign Up</label>
            </div>
            {signupStatus === "disabled" && !isRegistering && error !== SIGNUP_UNAVAILABLE && (
              <p className="signup-unavailable-note">{SIGNUP_UNAVAILABLE}</p>
            )}
          </div>
        )}

        {error && <DismissibleError message={error} onDismiss={() => setError("")} />}
        {authNotice && !isRegistering && !isResetting && (
          <AuthNotice
            tone={authNotice.tone}
            title={authNotice.title}
            noticeKey={authNotice.key}
            onDismiss={() => setAuthNotice(null)}
          >
            {authNotice.text}
          </AuthNotice>
        )}

        {isResetting ? (
          <PasswordResetFlow onDone={closePasswordReset} onBack={() => closePasswordReset()} />
        ) : isRegistering ? renderRegistrationStep() : (
          <form onSubmit={handleLogin}>
            <div className="field">
              <label htmlFor="username">Username or Email</label>
              <input id="username" ref={usernameInputRef} className="login-credential-input" type="text" value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="username" autoFocus required />
            </div>
            <div className="field">
              <label htmlFor="password">Password</label>
              <PasswordInput
                id="password"
                ref={passwordInputRef}
                className="login-credential-input"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                autoComplete="current-password"
                required
              />
            </div>
            {turnstileEnabled && !firstLoginGrace && (
              <TurnstileWidget
                action="login"
                onToken={setLoginTurnstileToken}
                onError={setError}
                resetSignal={loginTurnstileReset}
              />
            )}
            <button
              type="submit"
              className="btn btn-primary btn-block"
              disabled={submitting || (loginNeedsToken && !loginTurnstileToken)}
            >
              {submitting ? "Signing in..." : !loginNeedsToken || loginTurnstileToken ? "Sign In" : "Checking your browser..."}
            </button>
            <button type="button" className="link-button registration-back" onClick={openPasswordReset} disabled={submitting}>
              Forgot password?
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
