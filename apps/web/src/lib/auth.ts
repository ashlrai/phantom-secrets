import { createServiceClient } from "./supabase-server";
import { createClient, type User } from "@supabase/supabase-js";
import { createHash } from "crypto";

export interface AuthUser {
  userId: string;
  plan: string;
}

function effectivePlan(user: { plan: string; plan_expires_at?: string | null }) {
  if (
    user.plan === "pro" &&
    user.plan_expires_at &&
    new Date(user.plan_expires_at) < new Date()
  ) {
    return "free";
  }
  return user.plan;
}

/**
 * Resolve a GitHub login only from the provider identity maintained by
 * Supabase Auth. `user_metadata` is intentionally excluded because users can
 * edit it themselves and could otherwise impersonate another GitHub account.
 */
export function verifiedGithubLoginForUser(
  user: Pick<User, "identities">
): string | null {
  const githubIdentity = user.identities?.find(
    (identity) => identity.provider === "github"
  );
  const identityData = githubIdentity?.identity_data;
  const candidate =
    identityData?.user_name ??
    identityData?.preferred_username ??
    identityData?.login;

  if (typeof candidate !== "string") return null;
  const normalized = candidate.trim().replace(/^@+/, "").toLowerCase();
  if (!/^[a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?$/.test(normalized)) {
    return null;
  }
  return normalized;
}

/**
 * Validate a device token from the Authorization header.
 * Returns the user info or null if invalid.
 */
export async function authenticateRequest(
  req: Request
): Promise<AuthUser | null> {
  const authHeader = req.headers.get("authorization");
  if (!authHeader?.startsWith("Bearer ")) return null;

  const token = authHeader.slice(7);
  if (!token) return null;

  const tokenHash = createHash("sha256").update(token).digest("hex");
  const supabase = createServiceClient();

  const { data } = await supabase
    .from("device_tokens")
    .select("user_id, status, expires_at, token_expires_at")
    .eq("token_hash", tokenHash)
    .single();

  if (!data) return null;
  if (data.status !== "approved") return null;
  const expiresAt = data.token_expires_at ?? data.expires_at;
  if (new Date(expiresAt) < new Date()) return null;

  // Get user plan
  const { data: user } = await supabase
    .from("users")
    .select("plan, plan_expires_at")
    .eq("id", data.user_id)
    .single();

  if (!user) return null;

  return { userId: data.user_id, plan: effectivePlan(user) };
}

/**
 * Validate a Supabase browser session from the Authorization header.
 *
 * This is intentionally separate from authenticateRequest/requireAuth so CLI
 * API routes continue to require Phantom device tokens. Browser-only routes
 * such as Stripe checkout and the billing portal can opt in explicitly.
 */
export async function authenticateBrowserRequest(
  req: Request
): Promise<AuthUser | null> {
  const authHeader = req.headers.get("authorization");
  if (!authHeader?.startsWith("Bearer ")) return null;

  const token = authHeader.slice(7);
  if (!token) return null;

  const supabaseUser = createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    {
      auth: { persistSession: false },
      global: { headers: { Authorization: `Bearer ${token}` } },
    }
  );

  const {
    data: { user },
    error,
  } = await supabaseUser.auth.getUser();

  if (error || !user) return null;

  const supabase = createServiceClient();
  const githubLogin = verifiedGithubLoginForUser(user);
  if (!githubLogin) return null;

  const { error: upsertError } = await supabase.from("users").upsert(
    {
      id: user.id,
      github_login: githubLogin,
      email: user.email ?? null,
    },
    { onConflict: "id" }
  );

  if (upsertError) return null;

  const { data: dbUser } = await supabase
    .from("users")
    .select("plan, plan_expires_at")
    .eq("id", user.id)
    .single();

  if (!dbUser) return null;

  return { userId: user.id, plan: effectivePlan(dbUser) };
}

/**
 * Helper: require auth, return 401 Response if not authenticated.
 */
export async function requireAuth(
  req: Request
): Promise<AuthUser | Response> {
  const user = await authenticateRequest(req);
  if (!user) {
    return Response.json({ error: "unauthorized" }, { status: 401 });
  }
  return user;
}

/**
 * Helper: require Supabase browser auth without widening CLI API auth.
 */
export async function requireBrowserAuth(
  req: Request
): Promise<AuthUser | Response> {
  const user = await authenticateBrowserRequest(req);
  if (!user) {
    return Response.json({ error: "unauthorized" }, { status: 401 });
  }
  return user;
}

/**
 * Helper: require an approved pilot account.
 *
 * `pro` is a legacy database label, not proof that the cloud service has been
 * commissioned. Deny every request until pilot admission is backed by an
 * explicit, independently verifiable entitlement.
 */
export function requirePro(_user: AuthUser): Response | null {
  return Response.json(
    {
      error: "feature_unavailable",
      message:
        "This cloud capability is not commissioned. Contact Phantom to register pilot interest.",
      interest_url:
        "mailto:mason@ashlr.ai?subject=Phantom%20Cloud%20pilot%20interest",
    },
    { status: 503 }
  );
}
