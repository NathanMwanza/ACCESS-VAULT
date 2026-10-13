/** variant: 'error' | 'warning' | 'info' | 'success' */
export default function Alert({ variant = 'info', title, children }) {
  const role = variant === 'error' ? 'alert' : 'status';
  return (
    <div className={`alert alert--${variant}`} role={role}>
      {title && <strong className="alert__title">{title}</strong>}
      <div>{children}</div>
    </div>
  );
}
