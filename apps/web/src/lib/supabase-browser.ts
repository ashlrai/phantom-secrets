"use client";

import { createClient, type SupabaseClient } from "@supabase/supabase-js";

// Browser-side Supabase client. Singleton so multiple components share
// the same auth session listener. Only NEXT_PUBLIC_* env vars — never
// the service role key.
let _client: SupabaseClient | null = null;

export function getBrowserClient(): SupabaseClient {
  if (!_client) {
    _client = createClient(
      process.env.NEXT_PUBLIC_SUPABASE_URL!,
      process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!
    );
  }
  return _client;
}
