import {
  noStoreJson,
  publicReadinessSnapshot,
  readinessSnapshot,
} from "@/lib/hosted-observability";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export function GET() {
  const snapshot = publicReadinessSnapshot();
  if (snapshot.status !== "configuration_ready") {
    const detail = readinessSnapshot();
    console.warn(
      "phantom-readiness-held",
      JSON.stringify({
        checks: detail.checks,
        build_identity_reasons: detail.build.unavailable_reasons,
        hosted_services: detail.hosted_services,
      }),
    );
  }
  return noStoreJson(
    snapshot,
    snapshot.status === "configuration_ready" ? 200 : 503,
  );
}
