import type { createServiceClient } from "../src/lib/supabase-server";
import type { OAuthStoreClient } from "../src/lib/vercel-oauth-foundation";

// Compile-time regression test: real Supabase PostgREST builders implement
// PromiseLike rather than Promise. This must continue accepting the exact
// createServiceClient() shape without a cast or an adapter.
type RealServiceClient = ReturnType<typeof createServiceClient>;
type AssertOAuthStoreCompatible<T extends OAuthStoreClient> = T;
type RealClientIsCompatible = AssertOAuthStoreCompatible<RealServiceClient>;

export type { RealClientIsCompatible };
