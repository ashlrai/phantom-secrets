import "server-only";

export type HostedService = "billing" | "personal_vaults" | "teams";

type HostedServiceConfig = {
  env: string;
  label: string;
};

const HOSTED_SERVICES: Record<HostedService, HostedServiceConfig> = {
  billing: {
    env: "PHANTOM_BILLING_ENABLED",
    label: "Phantom managed billing",
  },
  personal_vaults: {
    env: "PHANTOM_CLOUD_VAULTS_ENABLED",
    label: "Phantom personal cloud vaults",
  },
  teams: {
    env: "PHANTOM_TEAMS_ENABLED",
    label: "Phantom hosted teams",
  },
};

/**
 * Hosted services are admitted independently and only by an exact, server-side
 * value. Missing, malformed, and loosely truthy values all remain closed.
 *
 * Device authorization is part of the hosted Phantom Cloud trust boundary and
 * shares the personal-vault commissioning gate. The value-blind `/api/v1/me`
 * account status route remains available independently after authentication.
 */
export function isHostedServiceCommissioned(service: HostedService): boolean {
  return process.env[HOSTED_SERVICES[service].env] === "true";
}

export function requireHostedService(
  service: HostedService,
): Response | null {
  if (isHostedServiceCommissioned(service)) return null;

  return Response.json(
    {
      error: "feature_unavailable",
      service,
      message: `${HOSTED_SERVICES[service].label} is not commissioned.`,
    },
    {
      status: 503,
      headers: { "cache-control": "no-store" },
    },
  );
}
