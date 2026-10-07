import {useEffect, useId, useRef, useState} from "react";
import {acceptsIPv4Segment, joinIPv4Draft, parseIPv4Paste, splitIPv4Draft, validateIPv4Input} from "../../utils/ipv4Input";
import "./IPv4Input.css";

/** Controlled string input. onChange(value, validation) fires for incomplete drafts too. */
export default function IPv4Input({value = "", onChange, mode = "address", required = false,
  networkOnly = false, hostOnly = false, contiguousWildcard = false, disabled = false,
  readOnly = false, label = "IPv4", name, id, error, className = "", onBlur}) {
  const generatedId = useId();
  const inputId = id || generatedId;
  const refs = useRef([]);
  const [touched, setTouched] = useState(false);
  const [rejected, setRejected] = useState("");
  const [rejectedIndex, setRejectedIndex] = useState(null);
  const options = {mode, required, networkOnly, hostOnly, contiguousWildcard};
  const result = validateIPv4Input(value, options);
  const draft = splitIPv4Draft(value, mode);
  const fields = mode === "cidr" ? [...draft.octets, draft.prefix] : draft.octets;
  const addressResult = validateIPv4Input(draft.octets.join("."), {mode: "address", required});
  const basicCidrResult = mode === "cidr" ? validateIPv4Input(value, {mode: "cidr", required}) : null;
  const missingPrefix = mode === "cidr" && !draft.prefix && validateIPv4Input(draft.octets.join(".")).valid;
  const validationError = missingPrefix ? "Please enter Prefix (0–32)" : result.error;
  const message = error || rejected || (touched ? validationError : "");
  const showInvalid = Boolean(message);
  const constraintError = mode === "cidr" && basicCidrResult.valid && !result.valid;
  const addressInvalid = showInvalid && (
    Boolean(error)
    || (Boolean(rejected) && rejectedIndex !== 4)
    || !addressResult.valid
    || constraintError
  );
  const prefixInvalid = mode === "cidr" && showInvalid && (
    Boolean(error)
    || (Boolean(rejected) && rejectedIndex === 4)
    || (addressResult.valid && !result.valid && !constraintError)
  );
  useEffect(() => {
    refs.current[0]?.setCustomValidity(missingPrefix ? "" : error || validationError || "");
    if (mode === "cidr") refs.current[4]?.setCustomValidity(missingPrefix ? error || validationError : "");
  }, [error, validationError, missingPrefix, mode]);
  const focus = index => {refs.current[index]?.focus(); refs.current[index]?.select();};
  function emit(next) {
    const text = joinIPv4Draft(next, mode);
    setRejected("");
    setRejectedIndex(null);
    onChange?.(text, validateIPv4Input(text, options));
  }
  function update(index, text) {
    if (!acceptsIPv4Segment(text, index === 4)) {
      setRejected(index === 4 ? "Prefix must be 0–32" : "Each field only accepts 0–255");
      setRejectedIndex(index);
      return;
    }
    const next = {octets: [...draft.octets], prefix: draft.prefix};
    if (index === 4) next.prefix = text; else next.octets[index] = text;
    emit(next);
  }
  function paste(event, index) {
    if (disabled || readOnly) return;
    const text = event.clipboardData.getData("text");
    event.preventDefault();
    if (/^[0-9]+$/.test(text)) {
      const input = event.currentTarget;
      const next = fields[index].slice(0, input.selectionStart) + text + fields[index].slice(input.selectionEnd);
      update(index, next);
      return;
    }
    const next = parseIPv4Paste(text, mode);
    if (!next) {
      setRejected("Pasted value is not a valid IPv4 address");
      setRejectedIndex(index);
      return;
    }
    if (mode === "cidr" && !text.includes("/")) next.prefix = draft.prefix;
    emit(next);
    focus(mode === "cidr" ? 4 : index);
  }
  function key(event, index) {
    if (disabled || readOnly || event.ctrlKey || event.metaKey || event.altKey) return;
    const input = event.currentTarget;
    if ((event.key === "." && index < 3) || (event.key === "/" && mode === "cidr" && index < 4)) {
      event.preventDefault(); focus(event.key === "/" ? 4 : index + 1);
    } else if ((event.key === "Backspace" && !fields[index]) || (event.key === "ArrowLeft" && input.selectionStart === 0 && input.selectionEnd === 0)) {
      if (index > 0) {event.preventDefault(); focus(index - 1);}
    } else if (event.key === "ArrowRight" && input.selectionStart === fields[index].length && input.selectionEnd === fields[index].length && index < fields.length - 1) {
      event.preventDefault(); focus(index + 1);
    } else if (event.key.length === 1 && !/^[0-9]$/.test(event.key)) event.preventDefault();
  }
  function segment(part, index) {
    return (
          <span className="ipv4-input-part" key={index}>
            {index > 0 && index < 4 && <span aria-hidden="true" className="ipv4-input-separator">.</span>}
            <input id={index === 0 ? inputId : inputId + "-" + index} ref={node => {refs.current[index] = node;}}
              type="text" inputMode="numeric" autoComplete="off" spellCheck={false}
              aria-label={index === 4 ? label + " prefix" : label + " octet " + (index + 1)}
              aria-invalid={Boolean(error || rejected || (touched && !result.valid))}
              aria-describedby={message ? inputId + "-error" : index === 4 ? inputId + "-prefix-hint" : undefined}
              value={part} disabled={disabled} readOnly={readOnly}
              required={required || fields.some(field => field !== "")} maxLength={index === 4 ? 2 : 3}
              onInvalid={() => {setTouched(true); if (missingPrefix) focus(4);}}
              onChange={event => update(index, event.target.value)} onPaste={event => paste(event, index)}
              onKeyDown={event => key(event, index)} />
          </span>
    );
  }
  return (
    <div className={"ipv4-input " + className}>
      <div className={mode === "cidr"
        ? "ipv4-input-cidr"
        : `ipv4-input-fields${showInvalid ? " ipv4-input-fields-invalid" : ""}`}
        role="group" aria-label={label}
        onBlur={event => {
          if (!event.currentTarget.contains(event.relatedTarget)) {setTouched(true); onBlur?.(value, result);}
        }}>
        {mode === "cidr" ? <>
          <div className="ipv4-input-address-box">
            <div className={`ipv4-input-fields${addressInvalid ? " ipv4-input-fields-invalid" : ""}`}>
              {draft.octets.map(segment)}
            </div>
          </div>
          <span aria-hidden="true" className="ipv4-input-separator ipv4-input-slash">/</span>
          <div className="ipv4-input-prefix-box">
            <div className={`ipv4-input-fields${prefixInvalid ? " ipv4-input-fields-invalid" : ""}`}>
              {segment(draft.prefix, 4)}
            </div>
          </div>
        </> : fields.map(segment)}
      </div>
      {name && <input type="hidden" name={name} value={value} disabled={disabled} />}
      {message && <div id={inputId + "-error"} className="ipv4-input-error" role="alert">{message}</div>}
    </div>
  );
}
