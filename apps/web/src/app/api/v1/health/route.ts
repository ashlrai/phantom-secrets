import {
  noStoreJson,
  publicLivenessSnapshot,
} from "@/lib/hosted-observability";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export function GET() {
  return noStoreJson(publicLivenessSnapshot());
}
