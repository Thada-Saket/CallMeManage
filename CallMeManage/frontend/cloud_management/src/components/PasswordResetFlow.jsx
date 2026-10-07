import { useEffect, useState } from "react";
import DismissibleError from "./DismissibleError";
import {
  cancelPasswordReset,
  completePasswordReset,
  resendPasswordReset,
  startPasswordReset,
  verifyPasswordReset,
} from "../api/api_auth";
import { deadlineFrom, formatClock, maskEmail, secondsLeft } from "../utils/countdown";
import { PasswordPolicyHint } from "./FieldHelp";
import {
  ACCOUNT_PASSWORD_MAX_LENGTH,
  ACCOUNT_PASSWORD_MIN_LENGTH,
  accountPasswordChecks,
  isAccountPasswordValid,
} from "../utils/accountPassword";

/**
 * Forgot password: email -> 6-digit code -> new password.
 * onDone(email) returns to Sign In with a "Password changed" notice; onBack()
 * returns without one.
 * The code, reset token and passwords live only in React state.
 */
export default function PasswordResetFlow({ onDone, onBack }) {
  const [step, setStep] = useState("email");
  const [email, setEmail] = useState("");
  const [otp, setOtp] = useState("");
  const [challengeId, setChallengeId] = useState("");
  const [resetToken, setResetToken] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  // UX mirror of the backend account password policy (CM-09); the API enforces it regardless
  const passwordChecks = accountPasswordChecks(newPassword);
  const passwordValid = isAccountPasswordValid(newPassword);
  const passwordsMismatch = confirmPassword !== "" && newPassword !== confirmPassword;
  const [otpExpiresAt, setOtpExpiresAt] = useState(0);
  const [flowExpiresAt, setFlowExpiresAt] = useState(0);
  const [resendAvailableAt, setResendAvailableAt] = useState(0);
  const [ticketExpiresAt, setTicketExpiresAt] = useState(0);
  const [now, setNow] = useState(() => Date.now());
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [resending, setResending] = useState(false);

  function restart(message) {
    setStep("email");
    setOtp("");
    setChallengeId("");
    setResetToken("");
    setNewPassword("");
    setConfirmPassword("");
    setOtpExpiresAt(0);
    setFlowExpiresAt(0);
    setResendAvailableAt(0);
    setTicketExpiresAt(0);
    setNotice("");
    setError(message);
  }

  // 410: the server dropped this reset (expired, too many wrong codes, used).
  // 404: the code was right but no account uses this address.
  function handleFailure(err, fallback) {
    if (err.status === 410 || err.status === 404) {
      restart(err.detail || fallback);
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

  function leave() {
    if (challengeId || resetToken) {
      cancelPasswordReset({ challengeId, resetToken }).catch(() => {});
    }
    onBack();
  }

  const timedStep = step === "otp" || step === "password";
  useEffect(() => {
    if (!timedStep) return undefined;
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [timedStep]);

  const activeDeadline = step === "otp" ? flowExpiresAt : step === "password" ? ticketExpiresAt : 0;
  useEffect(() => {
    if (activeDeadline && now >= activeDeadline) {
      restart("Verification time ran out. Please start again");
    }
  }, [activeDeadline, now]);

  async function handleStart(event) {
    event.preventDefault();
    setError("");
    setSubmitting(true);
    try {
      const result = await startPasswordReset(email.trim());
      setChallengeId(result.challenge_id);
      applyChallengeTimings(result);
      setOtp("");
      setNotice("");
      setStep("otp");
    } catch (err) {
      handleFailure(err, "Could not send the reset code");
    } finally {
      setSubmitting(false);
    }
  }

  async function handleResend() {
    setError("");
    setNotice("");
    setResending(true);
    try {
      applyChallengeTimings(await resendPasswordReset(challengeId));
      setOtp("");
      setNotice("A new code was sent. Earlier codes no longer work.");
    } catch (err) {
      handleFailure(err, "Could not send a new code");
    } finally {
      setResending(false);
    }
  }

  async function handleVerify(event) {
    event.preventDefault();
    setError("");
    setSubmitting(true);
    try {
      const result = await verifyPasswordReset(challengeId, otp);
      setResetToken(result.reset_token);
      setTicketExpiresAt(deadlineFrom(result.expires_in));
      setChallengeId("");
      setNow(Date.now());
      setStep("password");
    } catch (err) {
      handleFailure(err, "Could not verify the code");
    } finally {
      setSubmitting(false);
    }
  }

  async function handleComplete(event) {
    event.preventDefault();
    setError("");
    if (!isAccountPasswordValid(newPassword)) {
      setError("Password does not meet all requirements");
      return;
    }
    if (newPassword !== confirmPassword) {
      setError("Passwords do not match");
      return;
    }
    setSubmitting(true);
    try {
      await completePasswordReset(resetToken, newPassword);
      onDone(email.trim());
    } catch (err) {
      handleFailure(err, "Could not change the password");
      setSubmitting(false);
    }
  }

  function renderStep() {
    if (step === "email") {
      return (
        <form onSubmit={handleStart}>
          <p className="registration-step-copy">
            Enter the email you signed up with. We will send you a 6-digit code.
          </p>
          <div className="field">
            <label htmlFor="reset-email">Email</label>
            <input
              id="reset-email"
              type="email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              autoComplete="email"
              autoFocus
              required
            />
          </div>
          <button type="submit" className="btn btn-primary btn-block" disabled={submitting}>
            {submitting ? "Sending code..." : "Send reset code"}
          </button>
          <button type="button" className="link-button registration-back" onClick={leave} disabled={submitting}>
            Back to Sign In
          </button>
        </form>
      );
    }

    if (step === "otp") {
      const otpSecondsLeft = secondsLeft(otpExpiresAt, now);
      const resendSecondsLeft = secondsLeft(resendAvailableAt, now);
      const codeExpired = otpSecondsLeft === 0;
      return (
        <form onSubmit={handleVerify}>
          <p className="registration-step-copy">
            We sent an email to <strong>{maskEmail(email)}</strong>. Enter the 6-digit code from it to continue.
          </p>
          {notice && <p className="registration-notice" role="status">{notice}</p>}
          <div className="field">
            <label htmlFor="reset-otp">Verification Code</label>
            <input
              id="reset-otp"
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
            {submitting ? "Verifying..." : "Verify code"}
          </button>
          <div className="registration-actions">
            <button
              type="button"
              className="link-button"
              onClick={handleResend}
              disabled={resending || submitting || resendSecondsLeft > 0}
            >
              {resending
                ? "Sending..."
                : resendSecondsLeft > 0
                  ? `Resend code in ${formatClock(resendSecondsLeft)}`
                  : "Resend code"}
            </button>
            <button type="button" className="link-button" onClick={leave} disabled={submitting}>
              Cancel
            </button>
          </div>
        </form>
      );
    }

    return (
      <form onSubmit={handleComplete}>
        <div className="verified-email" title={email}>
          <span aria-hidden="true">✓</span> {email.trim()}
        </div>
        <div className="field">
          <div className="field-label-with-hint">
            <label htmlFor="reset-new-password">New Password</label>
            <PasswordPolicyHint checks={passwordChecks} invalid={newPassword !== "" && !passwordValid} />
          </div>
          <input
            id="reset-new-password"
            type="password"
            value={newPassword}
            onChange={(event) => setNewPassword(event.target.value)}
            autoComplete="new-password"
            minLength={ACCOUNT_PASSWORD_MIN_LENGTH}
            maxLength={ACCOUNT_PASSWORD_MAX_LENGTH}
            aria-invalid={newPassword !== "" && !passwordValid}
            autoFocus
            required
          />
        </div>
        <div className="field">
          <label htmlFor="reset-confirm-password">Confirm New Password</label>
          <input
            id="reset-confirm-password"
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
        <button type="submit" className="btn btn-primary btn-block" disabled={submitting || !passwordValid || newPassword !== confirmPassword}>
          {submitting ? "Saving..." : "Change password"}
        </button>
        <p className="registration-timer registration-timer-footer">
          Finish within {formatClock(secondsLeft(ticketExpiresAt, now))}
        </p>
        <button type="button" className="link-button registration-back" onClick={leave} disabled={submitting}>
          Cancel
        </button>
      </form>
    );
  }

  return (
    <>
      {error && <DismissibleError message={error} onDismiss={() => setError("")} />}
      {renderStep()}
    </>
  );
}
