import { createServiceClient } from "@/lib/supabase-server";
import { formatDeviceUserCode } from "@/lib/device-code";
import { createHash, randomUUID, randomInt } from "crypto";

// Characters that are easy to read aloud — no O/0, I/1, L confusion
const CODE_CHARS = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";

function generateUserCode(): string {
  let s = "";
  for (let i = 0; i < 8; i++) {
    s += CODE_CHARS[randomInt(CODE_CHARS.length)];
  }
  return s;
}

function clientRateLimitKey(req: Request): string | null {
  // Vercel documents x-vercel-forwarded-for as its non-spoofable client-IP
  // header even when another proxy sits in front of the deployment.
  const raw =
    req.headers.get("x-vercel-forwarded-for") ??
    req.headers.get("x-forwarded-for") ??
    req.headers.get("x-real-ip");
  const address = raw?.split(",", 1)[0]?.trim();
  if (!address || address.length > 64 || !/^[0-9a-f:.]+$/i.test(address)) {
    return null;
  }
  return createHash("sha256")
    .update(`phantom-device-init-v1\0${address}`)
    .digest("hex");
}

function noStoreJson(body: object, init?: ResponseInit) {
  const headers = new Headers(init?.headers);
  headers.set("cache-control", "no-store");
  return Response.json(body, { ...init, headers });
}

export async function POST(req: Request) {
  const supabase = createServiceClient();
  const clientKeyHash = clientRateLimitKey(req);
  if (!clientKeyHash) {
    return noStoreJson(
      { error: "Unable to establish a trusted client address." },
      { status: 400 }
    );
  }

  const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

  for (let attempt = 0; attempt < 5; attempt++) {
    const deviceCode = randomUUID();
    const userCode = generateUserCode();

    const { data: outcome, error } = await supabase.rpc("issue_device_code", {
      p_client_key_hash: clientKeyHash,
      p_device_code: deviceCode,
      p_user_code: userCode,
      p_expires_at: expiresAt.toISOString(),
    });

    if (!error && outcome === "issued") {
      return noStoreJson({
        device_code: deviceCode,
        user_code: formatDeviceUserCode(userCode),
        verification_uri: "https://phm.dev/device",
        interval: 5,
        expires_in: 900,
      });
    }

    if (
      !error &&
      ["client_rate_limited", "global_rate_limited", "too_many_pending"].includes(
        outcome
      )
    ) {
      console.warn("device auth initiation throttled", { outcome });
      return noStoreJson(
        { error: "Too many requests. Try again later." },
        { status: 429, headers: { "retry-after": "60" } }
      );
    }

    if (!error) {
      return noStoreJson(
        { error: "Failed to create device code" },
        { status: 500 }
      );
    }

    // Unique collisions are rare but possible for user_code/device_code.
    // Retry with fresh values instead of surfacing a transient 500.
    if (error.code !== "23505") {
      return noStoreJson(
        { error: "Failed to create device code" },
        { status: 500 }
      );
    }
  }

  return noStoreJson(
    { error: "Failed to allocate device code" },
    { status: 503 }
  );
}
