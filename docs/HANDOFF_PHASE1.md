# Phase 1 handoff — Frontend (Login) — for Nokuthula

**What it does.** Register and Login screens that call a mocked `/auth/register` and `/auth/login`.
After success you land on a placeholder vault page showing who is signed in, with Sign out.

**How to use it.** `npm install && npm run dev`. Demo login: `demo@accessvault.test` /
`correct horse battery staple`. `npm test` runs 21 automated tests.

**What is not done yet.**
- Real crypto (fake, shape-correct values are used until Nathan's module is wired in Phase 2)
- Real endpoints (mock only)
- File explorer, share dialog, audit log, settings screens
- Inactivity timeout (Phase 5)

**Edge cases and expected behaviour**

| Case | Expected |
|---|---|
| Empty fields | Inline field errors, no request sent |
| Invalid email format | "Enter a valid email address." |
| Password under 12 chars (register) | Inline error, no request sent |
| Passwords don't match | "The two passwords do not match." |
| Duplicate email (`email_taken`) | Error shown on the email field |
| Wrong password or unknown email (`invalid_credentials`) | One generic message: "Incorrect email or password." |
| Network failure | "Could not reach the server..." (code `network_error`) |
| Refresh the page while signed in | Signed out (session is memory only) |
| Visit `/vault` while signed out | Redirected to `/login` |
| Password in request body | Never. Only `authSecret` is sent (tested) |

**Traceability (Table 4.1).** Usability: users never handle keys (all key work is behind
`cryptoBridge.js`). Server never receives plaintext/password (tested in `mockAuthApi.test.js`).
