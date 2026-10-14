import { useId } from 'react';

export default function TextField({ label, error, hint, id, ...inputProps }) {
  const autoId = useId();
  const inputId = id ?? autoId;
  const errorId = `${inputId}-error`;
  const hintId = `${inputId}-hint`;
  const describedBy = [error ? errorId : null, hint ? hintId : null].filter(Boolean).join(' ') || undefined;

  return (
    <div className={`field${error ? ' field--invalid' : ''}`}>
      <label htmlFor={inputId}>{label}</label>
      <input id={inputId} aria-invalid={error ? 'true' : undefined} aria-describedby={describedBy} {...inputProps} />
      {hint && !error && <p className="field__hint" id={hintId}>{hint}</p>}
      {error && <p className="field__error" id={errorId}>{error}</p>}
    </div>
  );
}
