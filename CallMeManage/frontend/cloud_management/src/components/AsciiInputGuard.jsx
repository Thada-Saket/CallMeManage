import {useEffect} from "react";
import {
  ASCII_TEXT_ERROR,
  ASCII_TEXT_GUIDANCE,
  isPrintableAscii,
  unsupportedAsciiCharacters,
} from "../utils/asciiText";

const INPUT_SELECTOR = 'input[type="text"], input:not([type]), input[type="password"], input[type="search"]';

function isGuardable(input) {
  if (!input?.matches?.(INPUT_SELECTOR)) return false;
  if (input.disabled || input.readOnly || input.dataset.allowNonAscii === "true") return false;
  // These are structured numeric controls which already own stricter validators.
  if (["numeric", "decimal", "tel"].includes(String(input.inputMode || "").toLowerCase())) return false;
  if (input.closest?.(".ipv4-input")) return false;
  return true;
}

function rememberOriginalAttribute(input, name) {
  const marker = originalAttributeMarker(name);
  if (marker in input.dataset) return;
  input.dataset[marker] = input.getAttribute(name) ?? "";
}

function restoreOriginalAttribute(input, name) {
  const marker = originalAttributeMarker(name);
  if (!(marker in input.dataset)) return;
  const original = input.dataset[marker];
  if (original) input.setAttribute(name, original);
  else input.removeAttribute(name);
  delete input.dataset[marker];
}

// DOMStringMap property names may not contain a hyphen. Attribute names such
// as aria-invalid therefore have to become asciiOriginalAriaInvalid rather
// than asciiOriginalAria-invalid (the latter throws a DOMException in Chrome).
function originalAttributeMarker(name) {
  const camelName = String(name).replace(/-([a-z])/g, (_, char) => char.toUpperCase());
  return `asciiOriginal${camelName[0].toUpperCase()}${camelName.slice(1)}`;
}

function removeGuard(input) {
  if (input.dataset.asciiInvalid === "true" && input.validationMessage === ASCII_TEXT_ERROR) {
    input.setCustomValidity("");
  }
  delete input.dataset.asciiGuard;
  delete input.dataset.asciiInvalid;
  delete input.dataset.asciiInvalidCharacters;
  restoreOriginalAttribute(input, "title");
  restoreOriginalAttribute(input, "aria-invalid");
  restoreOriginalAttribute(input, "aria-description");
}

export function validateAsciiInput(input) {
  if (!isGuardable(input)) {
    removeGuard(input);
    return true;
  }

  rememberOriginalAttribute(input, "title");
  rememberOriginalAttribute(input, "aria-invalid");
  rememberOriginalAttribute(input, "aria-description");
  input.dataset.asciiGuard = "true";

  const valid = isPrintableAscii(input.value);
  const originalTitle = input.dataset.asciiOriginalTitle;
  const message = valid ? ASCII_TEXT_GUIDANCE : ASCII_TEXT_ERROR;
  input.title = originalTitle ? `${originalTitle}\n${message}` : message;
  input.setAttribute("aria-description", message);

  if (valid) {
    if (input.dataset.asciiInvalid === "true" && input.validationMessage === ASCII_TEXT_ERROR) {
      input.setCustomValidity("");
    }
    delete input.dataset.asciiInvalid;
    delete input.dataset.asciiInvalidCharacters;
    const originalAriaInvalid = input.dataset.asciiOriginalAriaInvalid;
    if (originalAriaInvalid) input.setAttribute("aria-invalid", originalAriaInvalid);
    else input.removeAttribute("aria-invalid");
    return true;
  }

  input.dataset.asciiInvalid = "true";
  input.dataset.asciiInvalidCharacters = unsupportedAsciiCharacters(input.value).join("");
  input.setAttribute("aria-invalid", "true");
  input.setCustomValidity(ASCII_TEXT_ERROR);
  return false;
}

function scan(root) {
  if (root?.matches?.(INPUT_SELECTOR)) validateAsciiInput(root);
  root?.querySelectorAll?.(INPUT_SELECTOR).forEach(validateAsciiInput);
}

// One delegated guard covers current forms and forms mounted later in modals.
// It does not rewrite values: users can see/correct the unsupported characters,
// while setCustomValidity prevents an invalid form from being submitted.
export default function AsciiInputGuard() {
  useEffect(() => {
    const validateEventTarget = (event) => validateAsciiInput(event.target);
    const resetForm = (event) => window.setTimeout(() => scan(event.target), 0);

    scan(document);
    document.addEventListener("input", validateEventTarget, true);
    document.addEventListener("change", validateEventTarget, true);
    document.addEventListener("focusin", validateEventTarget, true);
    document.addEventListener("invalid", validateEventTarget, true);
    document.addEventListener("reset", resetForm, true);

    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        if (mutation.type === "childList") mutation.addedNodes.forEach(scan);
        else scan(mutation.target);
      });
    });
    observer.observe(document.body, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ["disabled", "readonly", "type", "inputmode", "data-allow-non-ascii"],
    });

    return () => {
      observer.disconnect();
      document.removeEventListener("input", validateEventTarget, true);
      document.removeEventListener("change", validateEventTarget, true);
      document.removeEventListener("focusin", validateEventTarget, true);
      document.removeEventListener("invalid", validateEventTarget, true);
      document.removeEventListener("reset", resetForm, true);
      document.querySelectorAll('[data-ascii-guard="true"]').forEach(removeGuard);
    };
  }, []);

  return null;
}
