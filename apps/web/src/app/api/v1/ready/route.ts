import { noStoreJson, readinessSnapshot } from "@/lib/hosted-observability";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export function GET() {
  const snapshot = readinessSnapshot();
  return noStoreJson(
    snapshot,
    snapshot.status === "configuration_ready" ? 200 : 503,
  );
}
