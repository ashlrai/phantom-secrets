// Anonymous usage ping: allowlisted payload, weekly cadence, opt-outs, internal tagging.
const assert = require("assert");
const { mkdtempSync, readFileSync, rmSync, writeFileSync } = require("fs");
const { tmpdir } = require("os");
const { join } = require("path");
const ping = require("../bin/usage-ping.js");

const quiet = { isTTY: false, write() {} };

async function run() {
  const dir = mkdtempSync(join(tmpdir(), "phantom-usage-ping-"));
  const file = join(dir, "usage-telemetry.json");
  try {
    const t0 = new Date("2026-11-24T07:00:00Z");
    const opts = (env = {}, now = t0) => ({ version: "0.8.11", env, now, file, stderr: quiet, platform: "darwin", arch: "arm64" });

    const p = ping.prepare(opts());
    assert.ok(p, "install ping is due on first run");
    assert.deepStrictEqual(Object.keys(p).sort(), ["arch", "env", "event", "install_id", "internal", "os", "schema", "tool", "version"]);
    assert.strictEqual(p.event, "install");
    assert.strictEqual(p.tool, "phantom-secrets");
    assert.match(p.install_id, /^[0-9a-f-]{36}$/);

    let body = null;
    const okFetch = async (_url, init) => { body = JSON.parse(init.body); return { status: 202 }; };
    assert.strictEqual(await ping.deliver(p, { env: {}, now: t0, file, fetchImpl: okFetch }), true);
    assert.strictEqual(body.install_id, p.install_id);
    assert.ok(JSON.parse(readFileSync(file, "utf8")).installSentAt);

    assert.strictEqual(ping.prepare(opts({}, new Date(t0.getTime() + 3 * 3600_000))), null, "nothing within a week");
    const active = ping.prepare(opts({}, new Date(t0.getTime() + 7 * 24 * 3600_000)));
    assert.strictEqual(active.event, "active");
    assert.strictEqual(active.install_id, p.install_id);

    for (const env of [{ ASHLR_TELEMETRY: "0" }, { PHANTOM_TELEMETRY: "off" }, { DO_NOT_TRACK: "1" }, { NODE_ENV: "test" }]) {
      assert.strictEqual(ping.disabledByEnv(env), true, JSON.stringify(env));
      assert.strictEqual(ping.prepare(opts(env, new Date("2027-06-01T00:00:00Z"))), null);
    }
    assert.strictEqual(ping.disabledByEnv({ DO_NOT_TRACK: "0" }), false);

    writeFileSync(file, JSON.stringify({ disabled: true }));
    assert.strictEqual(ping.prepare(opts()), null, "disabled in state file");

    rmSync(file, { force: true });
    const ci = ping.prepare(opts({ GITHUB_ACTIONS: "true", GITHUB_REPOSITORY_OWNER: "ashlrai" }));
    assert.strictEqual(ci.env, "ci");
    assert.strictEqual(ci.internal, true);
    assert.strictEqual(ping.isInternal({ ASHLR_INTERNAL: "1" }, {}), true);
    assert.strictEqual(ping.isInternal({}, {}), false);

    rmSync(file, { force: true });
    const down = ping.prepare(opts());
    assert.strictEqual(await ping.deliver(down, { env: {}, now: t0, file, fetchImpl: async () => { throw new Error("offline"); } }), false);
    assert.strictEqual(ping.prepare(opts({}, new Date(t0.getTime() + 60_000))), null, "retries at most hourly");
    assert.ok(ping.prepare(opts({}, new Date(t0.getTime() + 2 * 3600_000))), "retries after an hour");

    assert.strictEqual(ping.prepare({ ...opts(), file: join(dir, "missing", "\0bad") }), null, "unwritable state sends nothing");

    rmSync(file, { force: true });
    const lines = [];
    const tty = { isTTY: true, write: (s) => lines.push(s) };
    ping.prepare({ ...opts(), stderr: tty });
    ping.prepare({ ...opts({}, new Date(t0.getTime() + 2 * 3600_000)), stderr: tty });
    assert.strictEqual(lines.length, 1, "notice printed once");
    assert.match(lines[0], /ASHLR_TELEMETRY=0/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  console.log("ok: usage ping");
}

run().catch((error) => { console.error(error); process.exit(1); });
