# Access Vault — Frontend (Dalitso)

React + Vite single-page app. Phase 1 scope: scaffold, Register and Login screens, wired to a
**mock** of `/auth/register` and `/auth/login` shaped exactly like the API & Data Agreements sheet.

## Run it

```bash
npm install
npm run dev      # http://localhost:5173
npm test         # tests (validation, mock-vs-contract, full UI flows)
npm run build
```

Demo account in mock mode: `demo@accessvault.test` / `correct horse battery staple`
(or just register a new one; mock users live in memory until you refresh).

## Using the real Supabase backend

Full steps are in [`docs/SUPABASE_SETUP.md`](docs/SUPABASE_SETUP.md). In short: run
`supabase/migrations/001_auth_integration.sql` once, then in `.env.local` set

```
VITE_USE_MOCK=false
VITE_SUPABASE_URL=https://<project-ref>.supabase.co
VITE_SUPABASE_PUBLISHABLE_KEY=<publishable key>
```

and restart `npm run dev`. `src/services/authApi.js` picks mock or Supabase; no page changes.
The tests always use the mock (plus a fake Supabase client for `supabaseAuthApi`).

## Folder map

```
src/
  crypto/          Nathan's module lands here (UI never imports it directly)
  components/      Reusable UI: TextField, PasswordField, Button, Alert, AuthLayout, ...
  pages/           LoginPage, RegisterPage, VaultPlaceholderPage (file explorer comes in Phase 3)
  context/         AuthContext: session held in memory only (no localStorage/cookies)
  services/
    contract.js      The API Agreements sheet as code: error codes, shape + size checks
    apiClient.js     ApiError class (the old fetch wrapper is unused now that the backend is Supabase)
    authApi.js       mock <-> Supabase switch
    supabaseClient.js     shared Supabase client (memory-only session, lazy)
    supabaseAuthApi.js    register / login / getAuthParams / logout against Supabase
    supabaseFoldersApi.js folder calls for the temporary Backend check panel
    mock/            Mock API + fake crypto (shape-correct, NOT secure)
    cryptoBridge.js  The only file the UI uses for crypto; swap in Nathan's setupAccount() here
  utils/           validation, password strength, base64
  styles/          theme.css (brand colours + derived tokens, change the look here) + global.css
supabase/          Prince's area: migrations/, schema_reference.sql, policies.sql
tests/             Vitest + Testing Library
docs/              Handoff overview for Nokuthula, open questions, Chapter 5 notes
```

## Rules this code follows (from the agreements sheet and Chapter 4)

- Frontend only ever sees **camelCase**; Prince converts to snake_case at the boundary.
- All binary values are **base64 strings**.
- Errors are `{ error, message }`; the UI branches on `error` and may show `message` directly.
- Frontend validation is **UX only**; the backend and Postgres RLS are the real security boundary.
- The password never leaves the device and is never put in a request body or stored.
- Login failure is one generic message and never reveals which field was wrong.
- Session is **memory only**: refresh or closing the tab signs you out.

## Branding

- Brand colours live in `src/styles/theme.css`: primary `#1D68FF`, secondary `#14181C`, tertiary `#F9F8F9`.
  Surfaces, borders and muted text are derived from them, so editing the three values re-themes the app.
- Logo files (traced from the supplied artwork to clean vector SVG, transparent background) are in `public/`:
  `logo-mark.svg` (icon), `logo-full.svg` (icon + wordmark), `favicon.svg`, plus `favicon-32.png`,
  `apple-touch-icon.png` and `logo-mark-512.png` fallbacks.
- `src/components/Logo.jsx` renders the mark with the name as live text.
