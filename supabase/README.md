# supabase/ - owned by Prince

| File | What it is |
|---|---|
| `schema_reference.sql` | Table definitions exported from the Supabase project. For reference, not meant to be re-run. |
| `policies.sql` | Phase 1 Row Level Security policies (owner-only). |
| `migrations/001_auth_integration.sql` | Run once. Sign-up trigger, `get_auth_params()` and the `users` column lock. |

See `docs/SUPABASE_SETUP.md` for the order to run things in.
