export default function Button({ children, loading = false, variant = 'primary', ...props }) {
  return (
    <button
      className={`btn btn--${variant}`}
      disabled={loading || props.disabled}
      aria-busy={loading || undefined}
      {...props}
    >
      {loading && <span className="spinner" aria-hidden="true" />}
      <span>{children}</span>
    </button>
  );
}
