import { createServiceClient } from "@/lib/supabase-server";
import { randomUUID } from "crypto";

// Characters that are easy to read aloud — no O/0, I/1, L confusion
const CODE_CHARS = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";

function generateUserCode(): string {
  const part = (len: number) => {
    let s = "";
    for (let i = 0; i < len; i++) {
      s += CODE_CHARS[Math.floor(Math.random() * CODE_CHARS.length)];
    }
    return s;
  };
  return `${part(4)}-${part(4)}`;
}

export async function POST() {
  const supabase = createServiceClient();
  const deviceCode = randomUUID();
  const userCode = generateUserCode();
  const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

  const { error } = await supabase.from("device_tokens").insert({
    device_code: deviceCode,
    user_code: userCode,
    status: "pending",
    expires_at: expiresAt.toISOString(),
  });

  if (error) {
    return Response.json({ error: "Failed to create device code" }, { status: 500 });
  }

  return Response.json({
    device_code: deviceCode,
    user_code: userCode,
    verification_uri: "https://phm.dev/device",
    interval: 5,
    expires_in: 900,
  });
}
