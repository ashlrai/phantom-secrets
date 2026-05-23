import { createServiceClient } from "@/lib/supabase-server";
import { formatDeviceUserCode } from "@/lib/device-code";
import { randomUUID, randomInt } from "crypto";

// Characters that are easy to read aloud — no O/0, I/1, L confusion
const CODE_CHARS = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";

function generateUserCode(): string {
  let s = "";
  for (let i = 0; i < 8; i++) {
    s += CODE_CHARS[randomInt(CODE_CHARS.length)];
  }
  return s;
}

export async function POST(req: Request) {
  const supabase = createServiceClient();

  // Rate limit: max 10 device codes created per minute (globally, since Vercel is serverless)
  const oneMinAgo = new Date(Date.now() - 60 * 1000).toISOString();
  const { count } = await supabase
    .from("device_tokens")
    .select("*", { count: "exact", head: true })
    .gte("created_at", oneMinAgo);

  if ((count ?? 0) >= 10) {
    return Response.json(
      { error: "Too many requests. Try again in a minute." },
      { status: 429 }
    );
  }

  const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

  for (let attempt = 0; attempt < 5; attempt++) {
    const deviceCode = randomUUID();
    const userCode = generateUserCode();

    const { error } = await supabase.from("device_tokens").insert({
      device_code: deviceCode,
      user_code: userCode,
      status: "pending",
      expires_at: expiresAt.toISOString(),
      device_expires_at: expiresAt.toISOString(),
    });

    if (!error) {
      return Response.json({
        device_code: deviceCode,
        user_code: formatDeviceUserCode(userCode),
        verification_uri: "https://phm.dev/device",
        interval: 5,
        expires_in: 900,
      });
    }

    // Unique collisions are rare but possible for user_code/device_code.
    // Retry with fresh values instead of surfacing a transient 500.
    if (error.code !== "23505") {
      return Response.json({ error: "Failed to create device code" }, { status: 500 });
    }
  }

  return Response.json({ error: "Failed to allocate device code" }, { status: 503 });
}
