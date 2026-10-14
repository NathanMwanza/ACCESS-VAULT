# Connecting the frontend to Supabase

## How login and registration work now

The browser never sends the real password. It derives `authSecret` from it (Algorithm 4.1) and gives
that to Supabase Auth as the "password". Supabase hashes it again before storing it.

**Register**
1. Browser: derive keys, build the registration payload (`prepareRegistration`).
2. `supabase.auth.signUp({ email, password: authSecret, options: { data: { name, kdf_salt, kdf_iterations, public_key, wrapped_private_key } } })`.
3. Database trigger `handle_new_user` copies those fields into `public.users`.

**Login**
1. `rpc('get_auth_params', { p_email })` returns the salt and iteration count (a fake one for unknown emails).
2. Browser: derive `authSecret` with that salt (`prepareLogin`).
3. `signInWithPassword({ email, password: authSecret })`.
4. Read the user's own `users` row (allowed by RLS) to get `salt` and `wrapped_private_key`.

The session lives in memory only. Refreshing the page signs you out, which is intended.

## One-time setup

1. **Find any existing sign-up trigger.** In the SQL Editor run:
   `select tgname, pg_get_triggerdef(oid) from pg_trigger where tgrelid = 'auth.users'::regclass and not tgisinternal;`
   If it is not named `on_auth_user_created`, add a `drop trigger if exists <name> on auth.users;` line to the migration.
2. **Change the pepper** in `get_auth_params` (the `v_pepper` line) to your own long random string.
3. **Run `supabase/migrations/001_auth_integration.sql`** in the SQL Editor.
4. **Delete the old test accounts** (they were created with a plain password). The optional clean-up block at the bottom of the migration does it, but it wipes all data.
5. **Email confirmation:** Authentication > Sign In / Providers > Email. For development and demos turn *Confirm email* off, otherwise every new account needs a working email link. Leave password requirements at their defaults.
6. **Configure the frontend:** `cp .env.example .env.local`, fill in the URL and publishable key, set `VITE_USE_MOCK=false`.
7. `npm install` then `npm run dev`.

## Checking it works

| # | Test | Expected |
|---|---|---|
| 1 | Register a new account | Lands on the vault page; a row appears in `public.users` with a salt and public key |
| 2 | In Authentication > Users, inspect the new user | Stored password is a hash; the real password appears nowhere |
| 3 | Sign out, sign in again | Works; wrong password gives the generic "Incorrect email or password" |
| 4 | Register the same email twice | "An account with this email already exists" |
| 5 | Backend check > Create test folder | Folder listed; `owner_id` equals your user id |
| 6 | Sign in as a second user, Load my folders | Does not see the first user's folders (RLS) |
| 7 | Refresh the page | Signed out |
| 8 | Browser dev tools > Network, register request body | Contains `authSecret`-derived value, never the typed password |

Record results (pass/fail, date, who) in this table for the test log.

## Security notes

- Only the publishable key is in the frontend. The service_role key never goes in the repo or the browser.
- `users` UPDATE is limited to the `name` column, so nobody can change their own `role`, keys or email.
- The `shares` INSERT policy checks `shared_by = auth.uid()` but not that the sharer owns the resource. Harmless while access is owner-only, but add that check before sharing grants access (Phase 3).
- `audit_logs` has no INSERT policy, so the client cannot write audit entries. Write them from a trigger or a `security definer` function.
- Storage bucket policies for encrypted chunks are not covered here.
