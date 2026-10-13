# Open questions to settle with the team before Phase 2

## 1. Login needs the salt before it can build `authSecret` (needs Nathan + Prince)

Algorithm 4.1 derives `authSecret = HKDF(PBKDF2(password, salt))`. The salt is random per user and is
stored on the server. But the agreed `POST /auth/login` takes `{ email, authSecret }` and only
**returns** `kdfSalt`. At login time the browser doesn't have the salt, so it can't compute `authSecret`.

Options:
- **A (recommended):** add `GET /auth/salt?email=` (or `POST /auth/params`) returning `{ kdfSalt, kdfIterations }`.
  For unknown emails return a deterministic fake salt so the endpoint can't be used to find out who has an account.
  Then login stays exactly as agreed.
- **B:** make login two-step (request salt, then submit proof). More change for the same result.

Either way, per the working rules it must be added to the API Agreements sheet before anyone codes it.
The mock currently sidesteps this with a deterministic fake secret (`services/mock/mockCrypto.js`).

## 2. Password minimum

The UI currently requires 12 characters (`PASSWORD_MIN_LENGTH` in `utils/validation.js`).
Confirm Prince enforces the same, and put the number in the sheet.

## 3. UI look (needs Nathan, per Phase 1 plan)

Brand colours are now set (primary #1D68FF, secondary #14181C, tertiary #F9F8F9) with the new logo. Still confirm with Nathan before building further screens; all colours are tokens in `src/styles/theme.css`.

## 4. Where the real endpoints live

Are `/auth/register` and `/auth/login` Supabase Edge Functions or a separate server?
That sets `VITE_API_URL` and whether CORS needs configuring.
