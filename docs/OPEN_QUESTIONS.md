# Open questions to settle with the team before Phase 2

## 1. Login needs the salt before it can build `authSecret` (needs Nathan + Prince)

> **Resolved in code, still needs sign-off on the sheet.** Option A is implemented as the Supabase
> function `get_auth_params(email)` (`supabase/migrations/001_auth_integration.sql`), called through
> `authApi.getAuthParams`. Add it to the API Agreements sheet.

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
The backend cannot enforce this: it only ever sees `authSecret`, never the password. So the minimum
is frontend-only by design. Put the number in the sheet and say so.

## 3. UI look (needs Nathan, per Phase 1 plan)

Brand colours are now set (primary #1D68FF, secondary #14181C, tertiary #F9F8F9) with the new logo. Still confirm with Nathan before building further screens; all colours are tokens in `src/styles/theme.css`.

## 4. Where the real endpoints live

**Resolved:** there are no custom endpoints. The app talks to Supabase directly (Auth + Postgres under
RLS). `VITE_API_URL` is gone; use `VITE_SUPABASE_URL` and `VITE_SUPABASE_PUBLISHABLE_KEY`.

## 5. Public key format (needs Nathan)

Chapter 4 describes RSA-OAEP (3072-bit). The frontend contract expects a raw P-256 key (65 bytes).
`users.public_key` is `text`, so the database accepts either, but pick one and update whichever document is wrong.

## 6. Looking up a recipient's public key for sharing (Phase 3, Prince)

`users` RLS lets a person read only their own row, so the owner cannot fetch a recipient's public key.
Add a `security definer` function, for example `get_public_key(email)`, restricted to signed-in users.
