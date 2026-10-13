// Input validation for UX feedback ONLY (API Agreements #6).
// The backend re-validates, and Postgres RLS is the real authorization boundary.
// Keep these rules in step with whatever Prince enforces server-side.

export const PASSWORD_MIN_LENGTH = 12;
export const DISPLAY_NAME_MIN = 2;
export const DISPLAY_NAME_MAX = 60;

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

export function validateEmail(email) {
  const value = (email ?? '').trim();
  if (!value) return 'Enter your email address.';
  if (!EMAIL_RE.test(value)) return 'Enter a valid email address.';
  return null;
}

export function validateDisplayName(name) {
  const value = (name ?? '').trim();
  if (!value) return 'Enter your name.';
  if (value.length < DISPLAY_NAME_MIN) return `Name must be at least ${DISPLAY_NAME_MIN} characters.`;
  if (value.length > DISPLAY_NAME_MAX) return `Name must be at most ${DISPLAY_NAME_MAX} characters.`;
  return null;
}

export function validateNewPassword(password) {
  if (!password) return 'Choose a password.';
  if (password.length < PASSWORD_MIN_LENGTH) {
    return `Password must be at least ${PASSWORD_MIN_LENGTH} characters.`;
  }
  return null;
}

export function validatePasswordConfirmation(password, confirmation) {
  if (!confirmation) return 'Re-enter your password.';
  if (password !== confirmation) return 'The two passwords do not match.';
  return null;
}

/** Login only checks the field is filled in; it never judges password strength. */
export function validateLoginPassword(password) {
  if (!password) return 'Enter your password.';
  return null;
}

export function validateRegisterForm({ displayName, email, password, confirmation }) {
  const errors = {
    displayName: validateDisplayName(displayName),
    email: validateEmail(email),
    password: validateNewPassword(password),
    confirmation: validatePasswordConfirmation(password, confirmation),
  };
  Object.keys(errors).forEach((k) => errors[k] === null && delete errors[k]);
  return errors;
}

export function validateLoginForm({ email, password }) {
  const errors = {
    email: validateEmail(email),
    password: validateLoginPassword(password),
  };
  Object.keys(errors).forEach((k) => errors[k] === null && delete errors[k]);
  return errors;
}
