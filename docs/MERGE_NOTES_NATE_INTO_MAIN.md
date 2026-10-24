# Merge notes: Nate's authFlow wired into the app

Base: the `Nate` branch. What was broken and what changed:

| Problem | Fix |
|---|---|
| `AuthContext` imported `initAuthFlow` (does not exist) and `createFolder/createGrant/getVault` from `supabaseAuthApi.js` (not there) | `AuthContext` now calls `authFlow.configure({ backend: authApi })` and `authFlow.register/login/logout` |
| `register` called with `(email, password, {displayName})`; authFlow takes `(email, displayName, password)` | argument order fixed |
| `authApi.js` deleted but still imported by pages and tests | restored; now returns the full backend (auth + vault calls) |
| Vault calls did not exist on the backend | `src/services/supabaseVaultApi.js` + mock equivalents in `mockAuthApi.js` |
| DB could not store an encrypted folder name or a key grant | `supabase/migrations/002_vault_folders_and_grants.sql` (**run it in Supabase**) |
| Mock used fake crypto, so mock mode could not run the real flow | mock stores real keys, seeds the demo user with real keys, `mockCrypto.js` removed |
| `npm install` failed (`@vitejs/plugin-react@4` does not support Vite 8) | plugin-react `^6.1.2`; lockfile regenerated |
| Tests: 2 expected `'unknown'`, the code is `'unknown_error'` | tests corrected |
| Merge-conflict markers in `README.md` / `.gitignore` (main) | resolved |
| `env.download` (real project URL + key) and `src - Shortcut.lnk` in the repo | removed. Keep `.env.local` out of git; consider rotating the publishable key |

Behaviour notes
- If saving the vault folder fails during registration, `register()` still succeeds (the account exists) and
  `login()` creates the vault next time. `session.vaultFolderKey` is `null` until then; Phase 3 should call
  `loadVault()` before using it.
- The "Backend check" panel still writes plaintext folder names (`folders.name`). Those rows are ignored by
  `getVault()`. Remove the panel when the explorer lands, since plaintext names break the zero-trust claim.
- `docs/OPEN_QUESTIONS.md` #5 is settled in code: raw ECDH P-256 (65 bytes), not RSA-OAEP. Update Chapter 4.

Checks: `npm test` (38 tests), `npm run test:flow` (22), `npm run test:crypto`, `npm run build`.
