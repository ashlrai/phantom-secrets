import { createHash } from "node:crypto";

export function validOpaqueConfiguration(
  value: string | undefined,
  minimumLength = 16,
): boolean {
  if (
    !value ||
    value.length < minimumLength ||
    value.length > 8_192 ||
    value.trim() !== value
  ) {
    return false;
  }
  return !/[\u0000-\u0020\u007f]/.test(value);
}

function validSupabaseUrl(value: string | undefined): boolean {
  if (!value || value.length > 2_048 || value.trim() !== value) return false;
  try {
    const url = new URL(value);
    return (
      url.protocol === "https:" &&
      url.username === "" &&
      url.password === "" &&
      url.hostname.length > ".supabase.co".length &&
      url.hostname.endsWith(".supabase.co") &&
      (url.pathname === "" || url.pathname === "/") &&
      url.search === "" &&
      url.hash === ""
    );
  } catch {
    return false;
  }
}

export function publicAuthConfigurationReady(env: NodeJS.ProcessEnv): boolean {
  return (
    validSupabaseUrl(env.NEXT_PUBLIC_SUPABASE_URL) &&
    validOpaqueConfiguration(env.NEXT_PUBLIC_SUPABASE_ANON_KEY)
  );
}

export function publicAuthConfigurationFingerprint(
  env: NodeJS.ProcessEnv,
): string | null {
  if (!publicAuthConfigurationReady(env)) return null;
  return createHash("sha256")
    .update("phantom-public-auth-configuration-v1\0")
    .update(env.NEXT_PUBLIC_SUPABASE_URL ?? "")
    .update("\0")
    .update(env.NEXT_PUBLIC_SUPABASE_ANON_KEY ?? "")
    .digest("hex");
}
