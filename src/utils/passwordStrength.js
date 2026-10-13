// Lightweight strength meter for the Register screen (Table 4.10: "password strength indication").
// Heuristic only. It guides the user; it is not a security control.

const COMMON = ['password', 'passw0rd', '123456', 'qwerty', 'letmein', 'welcome', 'admin', 'iloveyou', 'accessvault'];

export const STRENGTH_LABELS = ['Very weak', 'Weak', 'Fair', 'Good', 'Strong'];

/** Returns { score: 0..4, label, hint } */
export function scorePassword(password = '') {
  if (!password) return { score: 0, label: STRENGTH_LABELS[0], hint: '' };

  const lower = password.toLowerCase();
  const hasCommon = COMMON.some((w) => lower.includes(w));
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((re) => re.test(password)).length;
  const uniqueChars = new Set(password).size;

  let points = 0;
  if (password.length >= 8) points += 1;
  if (password.length >= 12) points += 1;
  if (password.length >= 16) points += 1;
  if (classes >= 3) points += 1;
  if (uniqueChars < Math.max(4, password.length / 3)) points -= 1; // e.g. "aaaaaaaaaaaa"
  if (hasCommon) points -= 2;

  const score = Math.max(0, Math.min(4, points));

  let hint = '';
  if (hasCommon) hint = 'Avoid common words and patterns.';
  else if (password.length < 12) hint = 'Use at least 12 characters. A short passphrase works well.';
  else if (classes < 3) hint = 'Mix in capitals, numbers or symbols, or make it longer.';
  else if (score < 4) hint = 'Longer is stronger.';

  return { score, label: STRENGTH_LABELS[score], hint };
}
