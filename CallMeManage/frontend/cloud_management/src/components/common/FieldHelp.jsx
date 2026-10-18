// Same compact, focusable help affordance used by the CLI Generator.
export default function FieldHelp({ label, children }) {
  return (
    <span className="field-help">
      <button type="button" className="field-help-trigger" aria-label={label} onClick={(event) => { event.preventDefault(); event.stopPropagation(); }}>?</button>
      <span className="field-help-tooltip" role="tooltip">{children}</span>
    </span>
  );
}
