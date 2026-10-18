// One shared Supabase client, created on first use.
//
// Lazy on purpose: in mock mode (VITE_USE_MOCK=true, and in the tests) nothing
// here runs, so no Supabase URL or key is needed.
//
// persistSession: false keeps the session in memory only. Refreshing the page
// signs you out, which is what the design wants (keys also live only in memory).
// The key below is the PUBLISHABLE (anon) key. It is safe in the browser because
// Row Level Security is the real boundary. Never put the service_role key here.

import { createClient } from '@supabase/supabase-js';

let client = null;

export function getSupabase() {
  if (client) return client;

  const url = import.meta.env.VITE_SUPABASE_URL;
  const key = import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY;
  if (!url || !key) {
    throw new Error(
      'Supabase is not configured. Set VITE_SUPABASE_URL and VITE_SUPABASE_PUBLISHABLE_KEY in .env.local ' +
        '(see .env.example), then restart `npm run dev`.',
    );
  }

  client = createClient(url, key, {
    auth: { persistSession: false, autoRefreshToken: true, detectSessionInUrl: false },
  });
  return client;
}
