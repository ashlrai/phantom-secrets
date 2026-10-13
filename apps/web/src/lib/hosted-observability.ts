import "server-only";

import packageMetadata from "../../package.json";
import {
  isHostedServiceCommissioned,
  type HostedService,
} from "./commissioning";
import {
  publicAuthConfigurationFingerprint,
  validOpaqueConfiguration,
} from "./public-auth-configuration";

const RELEASE_VERSION_PATTERN = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;
const SOURCE_REVISION_PATTERN = /^[0-9a-f]{40}$/;
// Next config replaces this direct reference with the observed build literal.
// Runtime variables cannot repair a missing or dirty source observation.
const BUILD_SOURCE_REVISION = process.env.PHANTOM_BUILD_SOURCE_REVISION;
const DEPLOYMENT_ID_PATTERN = /^dpl_[0-9A-Za-z]{16,96}$/;
const DEPLOYMENT_ENVIRONMENTS = new Set([
  "production",
  "preview",
  "development",
]);

export type BuildIdentity = {
  identified: boolean;
  release_version: string | null;
  source_revision: string | null;
  deployment_environment: string | null;
  unavailable_reasons: BuildIdentityReason[];
};

export type BuildIdentityReason =
  | "release_version_missing_or_invalid"
  | "source_revision_missing_or_invalid"
  | "deployment_id_missing_or_invalid"
  | "deployment_environment_missing_or_invalid";

export type ConfigurationCheck = "ready" | "not_ready";
export type HostedServiceState =
  | "not_commissioned"
  | "configuration_incomplete"
  | "configuration_ready";

type HostedServiceReadiness = {
  state: HostedServiceState;
};

export type PublicLivenessSnapshot = {
  status: "alive";
  service: "phantom-web";
  release_version: string | null;
};

export type ReadinessSnapshot = {
  status: "configuration_ready" | "not_ready";
  service: "phantom-web";
  scope: "configuration_only";
  build: BuildIdentity;
  checks: {
    build_identity: ConfigurationCheck;
    core_auth_configuration: ConfigurationCheck;
  };
  hosted_services: Record<HostedService, HostedServiceReadiness>;
  acceptance: {
    provider: "not_checked";
    customer: "not_established";
  };
};

export type PublicReadinessSnapshot = {
  status: "configuration_ready" | "not_ready";
  service: "phantom-web";
  release_version: string | null;
};

function validatedValue(
  value: string | undefined,
  pattern: RegExp,
): string | null {
  if (!value || value.length > 128 || value.trim() !== value) return null;
  return pattern.test(value) ? value : null;
}

function validPatternConfiguration(
  value: string | undefined,
  pattern: RegExp,
): boolean {
  return Boolean(
    value &&
      value.length <= 512 &&
      value.trim() === value &&
      pattern.test(value),
  );
}

function coreAuthConfigurationReady(env: NodeJS.ProcessEnv): boolean {
  const runtimeFingerprint = publicAuthConfigurationFingerprint(env);
  return (
    runtimeFingerprint !== null &&
    process.env.PHANTOM_PUBLIC_AUTH_CONFIGURATION_FINGERPRINT ===
      runtimeFingerprint &&
    validOpaqueConfiguration(env.SUPABASE_SERVICE_ROLE_KEY)
  );
}

function billingConfigurationReady(env: NodeJS.ProcessEnv): boolean {
  return (
    validPatternConfiguration(
      env.STRIPE_SECRET_KEY,
      /^sk_(?:test|live)_[0-9A-Za-z_]{8,}$/,
    ) &&
    validPatternConfiguration(
      env.STRIPE_PRO_PRICE_ID,
      /^price_[0-9A-Za-z]{8,}$/,
    ) &&
    validPatternConfiguration(
      env.STRIPE_WEBHOOK_SECRET,
      /^whsec_[0-9A-Za-z]{8,}$/,
    )
  );
}

export type SourceBindingDiagnostic = {
  build_observation: "valid" | "missing_or_invalid";
  platform_source: "absent" | "invalid" | "matching" | "conflicting";
};

function readSourceBinding(env: NodeJS.ProcessEnv): {
  revision: string | null;
  diagnostic: SourceBindingDiagnostic;
} {
  const buildSourceRevision = validatedValue(
    BUILD_SOURCE_REVISION,
    SOURCE_REVISION_PATTERN,
  );
  const platformSourceRevision = validatedValue(
    env.VERCEL_GIT_COMMIT_SHA,
    SOURCE_REVISION_PATTERN,
  );
  // Only genuine absence may use the build observation. A present invalid or
  // conflicting platform revision remains a failed source identity.
  const sourceRevision =
    buildSourceRevision &&
    (env.VERCEL_GIT_COMMIT_SHA === undefined ||
      platformSourceRevision === buildSourceRevision)
      ? buildSourceRevision
      : null;
  return {
    revision: sourceRevision,
    diagnostic: {
      build_observation: buildSourceRevision ? "valid" : "missing_or_invalid",
      // A valid platform value with no valid build observation is unbound and
      // therefore conflicting. Matching requires both canonical values equal.
      platform_source:
        env.VERCEL_GIT_COMMIT_SHA === undefined
          ? "absent"
          : !platformSourceRevision
            ? "invalid"
            : buildSourceRevision === platformSourceRevision
              ? "matching"
              : "conflicting",
    },
  };
}

export function sourceBindingDiagnostic(
  env: NodeJS.ProcessEnv = process.env,
): SourceBindingDiagnostic {
  return readSourceBinding(env).diagnostic;
}

export function readBuildIdentity(
  env: NodeJS.ProcessEnv = process.env,
): BuildIdentity {
  const releaseVersion = validatedValue(
    packageMetadata.version,
    RELEASE_VERSION_PATTERN,
  );
  const sourceRevision = readSourceBinding(env).revision;
  const deploymentId = validatedValue(
    env.VERCEL_DEPLOYMENT_ID,
    DEPLOYMENT_ID_PATTERN,
  );
  const deploymentEnvironment = DEPLOYMENT_ENVIRONMENTS.has(
    env.VERCEL_ENV ?? "",
  )
    ? env.VERCEL_ENV ?? null
    : null;

  const unavailableReasons: BuildIdentityReason[] = [];
  if (!releaseVersion) {
    unavailableReasons.push("release_version_missing_or_invalid");
  }
  if (!sourceRevision) {
    unavailableReasons.push("source_revision_missing_or_invalid");
  }
  if (!deploymentId) {
    unavailableReasons.push("deployment_id_missing_or_invalid");
  }
  if (!deploymentEnvironment) {
    unavailableReasons.push("deployment_environment_missing_or_invalid");
  }
  const identified = unavailableReasons.length === 0;

  return {
    identified,
    // Build identity is deliberately all-or-nothing. A valid-looking fragment
    // must not be mistaken for proof of the deployment as a whole.
    release_version: identified ? releaseVersion : null,
    source_revision: identified ? sourceRevision : null,
    deployment_environment: identified ? deploymentEnvironment : null,
    unavailable_reasons: unavailableReasons,
  };
}

function publicReleaseVersion(): string | null {
  return validatedValue(packageMetadata.version, RELEASE_VERSION_PATTERN);
}

export function publicLivenessSnapshot(): PublicLivenessSnapshot {
  return {
    status: "alive",
    service: "phantom-web",
    release_version: publicReleaseVersion(),
  };
}

function hostedServiceReadiness(
  service: HostedService,
  coreConfigurationReady: boolean,
  env: NodeJS.ProcessEnv,
): HostedServiceReadiness {
  let state: HostedServiceState = "not_commissioned";
  if (isHostedServiceCommissioned(service)) {
    const serviceConfigurationReady =
      coreConfigurationReady &&
      (service !== "billing" || billingConfigurationReady(env));
    state = serviceConfigurationReady
      ? "configuration_ready"
      : "configuration_incomplete";
  }

  return { state };
}

export function readinessSnapshot(): ReadinessSnapshot {
  const env = process.env;
  const build = readBuildIdentity(env);
  const coreConfigurationReady = coreAuthConfigurationReady(env);
  const hostedServices = {
    billing: hostedServiceReadiness("billing", coreConfigurationReady, env),
    personal_vaults: hostedServiceReadiness(
      "personal_vaults",
      coreConfigurationReady,
      env,
    ),
    teams: hostedServiceReadiness("teams", coreConfigurationReady, env),
  } satisfies Record<HostedService, HostedServiceReadiness>;
  const enabledServicesConfigured = Object.values(hostedServices).every(
    ({ state }) => state !== "configuration_incomplete",
  );
  const configurationReady =
    build.identified && coreConfigurationReady && enabledServicesConfigured;

  return {
    status: configurationReady ? "configuration_ready" : "not_ready",
    service: "phantom-web",
    scope: "configuration_only",
    build,
    checks: {
      build_identity: build.identified ? "ready" : "not_ready",
      core_auth_configuration: coreConfigurationReady ? "ready" : "not_ready",
    },
    hosted_services: hostedServices,
    acceptance: {
      provider: "not_checked",
      customer: "not_established",
    },
  };
}

export function publicReadinessSnapshot(): PublicReadinessSnapshot {
  const snapshot = readinessSnapshot();
  return {
    status: snapshot.status,
    service: snapshot.service,
    release_version: publicReleaseVersion(),
  };
}

export function noStoreJson(body: object, status = 200): Response {
  return Response.json(body, {
    status,
    headers: { "cache-control": "no-store" },
  });
}
