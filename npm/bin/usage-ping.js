// Anonymous install / weekly-active ping for the phantom-secrets npm wrapper.
//
// Sent fields (and nothing else): schema, event, tool, version, os, arch,
// env (dev|ci), internal, install_id (random UUID made on first run).
// Never sent: paths, project or repo names, hostnames, usernames, commands,
// arguments, environment values, secrets or placeholders. IPs are not stored
// (the ashlr.ai ingest blanks them before analytics).
//
// Opt out: ASHLR_TELEMETRY=0 (false/off/no), PHANTOM_TELEMETRY=0, DO_NOT_TRACK=1,
// or "disabled": true in ~/.ashlr/usage-telemetry.json.
// Details: https://github.com/ashlrai/phantom/blob/master/docs/TELEMETRY.md
//
// The wrapper runs the native binary synchronously, so the ping runs in a
// detached child that is only spawned when one is due (at most weekly).

const { randomUUID } = require("crypto");
const { spawn } = require("child_process");
const { existsSync, mkdirSync, readFileSync, writeFileSync } = require("fs");
const { homedir } = require("os");
const { dirname, isAbsolute, join } = require("path");

const ENDPOINT = "https://ashlr.ai/api/telemetry";
const ACTIVE_INTERVAL_MS = 7 * 24 * 60 * 60 * 1000;
const RETRY_INTERVAL_MS = 60 * 60 * 1000;
const TIMEOUT_MS = 3000;
const FALSEY = new Set(["0", "false", "off", "no", "disabled"]);
const CI_VARS = ["CI", "GITHUB_ACTIONS", "GITLAB_CI", "BUILDKITE", "CIRCLECI", "JENKINS_URL", "TF_BUILD",
  "CODEBUILD_BUILD_ID", "TEAMCITY_VERSION", "BITBUCKET_BUILD_NUMBER", "DRONE", "VERCEL", "NETLIFY"];

const truthy = (v) => v !== undefined && v !== "" && !FALSEY.has(String(v).trim().toLowerCase());

function stateFile(env = process.env) {
  const configured = env.ASHLR_HOME;
  const home = configured && configured.trim() !== "" && isAbsolute(configured) ? configured : join(homedir(), ".ashlr");
  return join(home, "usage-telemetry.json");
}

function disabledByEnv(env = process.env) {
  for (const key of ["ASHLR_TELEMETRY", "PHANTOM_TELEMETRY"]) {
    const v = env[key];
    if (v !== undefined && FALSEY.has(v.trim().toLowerCase())) return true;
  }
  if (truthy(env.DO_NOT_TRACK)) return true;
  if (env.NODE_ENV === "test" || env.VITEST) return true;
  return false;
}

const isCi = (env = process.env) => CI_VARS.some((k) => truthy(env[k]));

function isInternal(env, state) {
  if (truthy(env.ASHLR_INTERNAL)) return true;
  if ((env.GITHUB_REPOSITORY_OWNER || "").toLowerCase() === "ashlrai") return true;
  return state.internal === true;
}

function readState(file) {
  try {
    if (!existsSync(file)) return {};
    const parsed = JSON.parse(readFileSync(file, "utf8"));
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

function writeState(file, state) {
  try {
    mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
    writeFileSync(file, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });
    return true;
  } catch {
    return false;
  }
}

function plan(state, now) {
  if (!state.installSentAt) return "install";
  const last = Date.parse(state.lastActiveAt || state.installSentAt);
  if (!Number.isFinite(last) || now.getTime() - last >= ACTIVE_INTERVAL_MS) return "active";
  return null;
}

const NOTICE =
  "phantom sends an anonymous install/weekly-active ping (tool, version, OS, arch, CI or not, random ID; " +
  "no secrets, paths, repos, IPs or personal data). Opt out: ASHLR_TELEMETRY=0 or DO_NOT_TRACK=1. " +
  "Details: https://github.com/ashlrai/phantom/blob/master/docs/TELEMETRY.md\n";

// Synchronous gate run in the wrapper: returns the payload to send or null.
// Writes the install id and attempt time first; if that fails nothing is sent.
function prepare({ version, env = process.env, now = new Date(), file = stateFile(env), stderr = process.stderr,
  platform = process.platform, arch = process.arch } = {}) {
  try {
    if (disabledByEnv(env)) return null;
    const state = readState(file);
    if (state.disabled === true) return null;
    const event = plan(state, now);
    if (!event) return null;
    const lastAttempt = Date.parse(state.lastAttemptAt || "");
    if (Number.isFinite(lastAttempt) && now.getTime() - lastAttempt < RETRY_INTERVAL_MS) return null;
    const next = { ...state, installId: state.installId || randomUUID(), lastAttemptAt: now.toISOString() };
    if (!next.noticeShownAt && stderr && stderr.isTTY) {
      stderr.write(NOTICE);
      next.noticeShownAt = now.toISOString();
    }
    if (!writeState(file, next)) return null;
    const token = (v) => (/^[a-z0-9_]{1,16}$/.test(v) ? v : "other");
    return {
      schema: 1,
      event,
      tool: "phantom-secrets",
      version: /^[0-9A-Za-z.+-]{1,40}$/.test(version || "") ? version : "unknown",
      os: token(platform),
      arch: token(arch),
      env: isCi(env) ? "ci" : "dev",
      internal: isInternal(env, state),
      install_id: next.installId,
    };
  } catch {
    return null;
  }
}

// Deliver a prepared payload and record success. Never throws.
async function deliver(payload, { env = process.env, now = new Date(), file = stateFile(env), fetchImpl = fetch } = {}) {
  try {
    const endpoint = (env.ASHLR_TELEMETRY_ENDPOINT || "").trim() || ENDPOINT;
    const res = await fetchImpl(endpoint, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    }).catch(() => null);
    if (!res || res.status >= 500) return false;
    const state = readState(file);
    if (payload.event === "install") state.installSentAt = now.toISOString();
    state.lastActiveAt = now.toISOString();
    writeState(file, state);
    return true;
  } catch {
    return false;
  }
}

// Called from the wrapper. Spawns a detached child only when a ping is due.
function schedule(version, { spawnImpl = spawn } = {}) {
  try {
    const payload = prepare({ version });
    if (!payload) return false;
    const child = spawnImpl(process.execPath, [__filename, JSON.stringify(payload)], {
      detached: true,
      stdio: "ignore",
      windowsHide: true,
    });
    child.on?.("error", () => {});
    child.unref?.();
    return true;
  } catch {
    return false;
  }
}

if (require.main === module) {
  let payload = null;
  try { payload = JSON.parse(process.argv[2] || "null"); } catch { payload = null; }
  if (payload && typeof payload === "object") deliver(payload).finally(() => process.exit(0));
}

module.exports = { ENDPOINT, NOTICE, deliver, disabledByEnv, isCi, isInternal, plan, prepare, schedule, stateFile };
