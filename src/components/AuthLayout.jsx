import Logo from './Logo.jsx';

/** Shared shell for Login and Register: brand panel + card. */
export default function AuthLayout({ title, subtitle, children, footer }) {
  return (
    <div className="auth-shell">
      <aside className="auth-brand" aria-hidden="true">
        <Logo size="lg" />
        <h2>Share files without sharing your secrets.</h2>
        <p>
          Your files are encrypted in your browser before they leave your device. The server
          only ever stores scrambled data.
        </p>
      </aside>

      <main className="auth-main">
        <div className="auth-card">
          <div className="auth-card__mobile-logo">
            <Logo />
          </div>
          <h1>{title}</h1>
          {subtitle && <p className="auth-card__subtitle">{subtitle}</p>}
          {children}
          {footer && <p className="auth-card__footer">{footer}</p>}
        </div>
      </main>
    </div>
  );
}
