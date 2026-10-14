import { scorePassword } from '../utils/passwordStrength.js';

export default function PasswordStrengthMeter({ password }) {
  if (!password) return null;
  const { score, label, hint } = scorePassword(password);
  return (
    <div className="strength" aria-live="polite">
      <div className="strength__bars" aria-hidden="true">
        {[1, 2, 3, 4].map((n) => (
          <span key={n} className={`strength__bar${score >= n ? ` strength__bar--on strength__bar--s${score}` : ''}`} />
        ))}
      </div>
      <p className="strength__label">
        Password strength: <strong>{label}</strong>
        {hint ? <span> — {hint}</span> : null}
      </p>
    </div>
  );
}
