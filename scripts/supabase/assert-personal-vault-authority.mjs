#!/usr/bin/env node
// Run only against the empty, replayed local CI database. Separate psql sessions
// and a held advisory barrier make quota/CAS overlap deterministic, not timing-based.
import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { randomBytes, randomInt } from "node:crypto";
import { promisify } from "node:util";

const port = Number(process.env.PHANTOM_CI_DB_PORT);
if (!Number.isInteger(port) || port < 1024 || port > 65535) {
  throw new Error("Set PHANTOM_CI_DB_PORT for the isolated local database");
}
const args = ["--no-psqlrc", "--host", "127.0.0.1", "--port", String(port), "--username", "postgres", "--dbname", "postgres", "--set", "ON_ERROR_STOP=1", "--tuples-only", "--no-align", "--quiet"];
const env = { PATH: process.env.PATH, PGPASSWORD: "postgres", PGCONNECT_TIMEOUT: "5", PGOPTIONS: "-c statement_timeout=10000 -c lock_timeout=8000" };
const execute = promisify(execFile);
async function query(sql, application = "phm_vault_fixture") {
  const result = await execute("psql", [...args, "--command", sql], {
    env: { ...env, PGAPPNAME: application }, timeout: 15_000, maxBuffer: 2 * 1024 * 1024,
  });
  return result.stdout.trim();
}
const ids = [
  "10000000-0000-4000-8000-000000000001",
  "10000000-0000-4000-8000-000000000002",
  "10000000-0000-4000-8000-000000000003",
];
const nonce = randomBytes(4).toString("hex");
const schema = `phm_vault_test_${nonce}`;
const trigger = `phm_vault_barrier_${nonce}`;
const barrierKey = randomInt(1, 2 ** 30);
const rpc = (user, project, blob, version) =>
  `SELECT json_build_object('outcome', outcome, 'version', version) FROM public.push_personal_vault('${user}', '${project}', '${blob}', ${version})`;
const asService = (sql) => `BEGIN; SET LOCAL ROLE service_role; ${sql}; COMMIT;`;

async function holdBarrier() {
  const child = spawn("psql", args, { env, stdio: ["pipe", "pipe", "pipe"] });
  let output = ""; let stderr = "";
  const finished = new Promise((done, fail) => {
    child.on("error", fail);
    child.on("exit", (code) => code === 0 ? done() : fail(new Error(`Local barrier failed: ${stderr}`)));
  });
  finished.catch(() => {});
  try {
    await new Promise((done, fail) => {
      const timer = setTimeout(() => fail(new Error("Local barrier acquisition timed out")), 5000);
      child.stdout.on("data", (chunk) => {
        output += chunk;
        if (output.includes("barrier-ready")) { clearTimeout(timer); done(); }
      });
      child.stderr.on("data", (chunk) => { stderr += chunk; });
      child.once("error", (error) => { clearTimeout(timer); fail(error); });
      child.once("exit", () => { clearTimeout(timer); fail(new Error("Local barrier exited before acquisition")); });
      child.stdin.write(`BEGIN; SELECT pg_advisory_xact_lock(${barrierKey}); SELECT 'barrier-ready';\n`);
    });
    return { release: async () => { child.stdin.end("COMMIT;\n"); await finished; }, kill: () => child.kill("SIGTERM") };
  } catch (error) { child.kill("SIGTERM"); throw error; }
}
async function race(sqls) {
  const barrier = await holdBarrier();
  const names = sqls.map((_, index) => `phm_vault_race_${nonce}_${index}`);
  const pending = Promise.all(sqls.map((sql, index) => query(asService(sql), names[index])));
  pending.catch(() => {});
  try {
    const deadline = Date.now() + 6000;
    let waiting = false;
    while (Date.now() < deadline) {
      const count = await query(`SELECT count(*) FROM pg_stat_activity WHERE application_name IN ('${names.join("','")}') AND wait_event_type = 'Lock'`);
      if (Number(count) === sqls.length) { waiting = true; break; }
      await new Promise((done) => setTimeout(done, 25));
    }
    assert.ok(waiting, "both real RPC sessions must overlap on locks before release");
    await barrier.release();
    return (await pending).map((text) => JSON.parse(text));
  } finally { barrier.kill(); await pending.catch(() => {}); }
}
async function denied(sql) {
  await assert.rejects(query(sql), (error) => /permission denied/.test(error.stderr ?? ""));
}

// Refuse before creating fixtures unless this is the expected empty local replay.
assert.equal(await query("SELECT count(*) FROM supabase_migrations.schema_migrations WHERE version = '20261009225441'"), "1");
assert.equal(await query("SELECT (SELECT count(*) FROM public.users) + (SELECT count(*) FROM public.vault_blobs) + (SELECT count(*) FROM auth.users)"), "0");
assert.equal(await query("SELECT NOT p.prosecdef AND 'search_path=pg_catalog' = ANY(p.proconfig) AND has_function_privilege('service_role', p.oid, 'EXECUTE') AND NOT has_function_privilege('anon', p.oid, 'EXECUTE') AND NOT has_function_privilege('authenticated', p.oid, 'EXECUTE') FROM pg_proc p WHERE p.oid = 'public.push_personal_vault(uuid,text,text,bigint)'::regprocedure"), "t");
assert.equal(await query("SELECT bool_and(has_table_privilege('service_role', target, privilege)) FROM (VALUES ('public.users','SELECT'),('public.users','UPDATE'),('public.vault_blobs','SELECT'),('public.vault_blobs','INSERT'),('public.vault_blobs','UPDATE')) AS required(target,privilege)"), "t");
assert.equal(await query("SELECT bool_and(has_table_privilege('service_role', target, privilege)) FROM (VALUES ('public.users','INSERT'),('public.device_tokens','SELECT'),('public.device_tokens','UPDATE')) AS required(target,privilege)"), "t");
assert.equal(await query("SELECT bool_and(relrowsecurity) FROM pg_class WHERE oid IN ('public.users'::regclass,'public.device_tokens'::regclass,'public.vault_blobs'::regclass)"), "t");
assert.equal(await query("SELECT count(*) = 11 AND bool_and(c.relrowsecurity) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p')"), "t");

let fixturesCreated = false;
try {
  await query(`BEGIN;
    INSERT INTO auth.users (id, email) VALUES ${ids.map((id, index) => `('${id}', 'vault-fixture-${index}@example.invalid')`).join(",")};
    INSERT INTO public.users (id, github_login, plan, plan_expires_at) VALUES
      ('${ids[0]}','vault-fixture-a','pro',now() + interval '1 year'),
      ('${ids[1]}','vault-fixture-b','free',NULL), ('${ids[2]}','vault-fixture-c','free',NULL);
    CREATE SCHEMA ${schema};
    CREATE FUNCTION ${schema}.block_writer() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
      BEGIN
        IF current_setting('application_name') LIKE 'phm_vault_race_%' THEN
          PERFORM pg_advisory_xact_lock(${barrierKey});
        END IF;
        RETURN NEW;
      END; $$;
    CREATE TRIGGER ${trigger} BEFORE INSERT OR UPDATE ON public.vault_blobs FOR EACH ROW EXECUTE FUNCTION ${schema}.block_writer();
    COMMIT;`);
  fixturesCreated = true;
  const created = await race([rpc(ids[0], "first-a", "fixture-a", 0), rpc(ids[0], "first-b", "fixture-b", 0)]);
  assert.deepEqual(created.map((row) => row.outcome).sort(), ["created", "quota_exceeded"]);
  assert.equal(await query(`SELECT count(*) FROM public.vault_blobs WHERE user_id = '${ids[0]}'`), "1");
  const duplicate = await race([rpc(ids[1], "same", "fixture-a", 0), rpc(ids[1], "same", "fixture-b", 0)]);
  assert.deepEqual(duplicate.map((row) => row.outcome).sort(), ["conflict", "created"]);
  assert.ok(duplicate.every((row) => row.version === 1));
  const updated = await race([rpc(ids[1], "same", "updated-a", 1), rpc(ids[1], "same", "updated-b", 1)]);
  assert.deepEqual(updated.map((row) => row.outcome).sort(), ["conflict", "updated"]);
  assert.ok(updated.every((row) => row.version === 2));
  assert.equal(await query(`SELECT version FROM public.vault_blobs WHERE user_id='${ids[1]}' AND project_id='same'`), "2");
  assert.ok(["updated-a", "updated-b"].includes(await query(`SELECT encrypted_blob FROM public.vault_blobs WHERE user_id='${ids[1]}' AND project_id='same'`)));
  assert.equal(JSON.parse(await query(asService(rpc(ids[0], "another", "fixture", 0)))).outcome, "quota_exceeded");

  await query(`INSERT INTO public.vault_blobs(user_id,project_id,encrypted_blob) VALUES ('${ids[2]}','legacy-one','fixture'),('${ids[2]}','legacy-two','fixture')`);
  for (const project of ["legacy-one", "legacy-two"]) {
    assert.deepEqual(JSON.parse(await query(asService(rpc(ids[2], project, "updated", 1)))), { outcome: "updated", version: 2 });
  }
  assert.equal(JSON.parse(await query(asService(rpc(ids[2], "new-third", "fixture", 0)))).outcome, "quota_exceeded");
  assert.equal(JSON.parse(await query(asService(rpc("10000000-0000-4000-8000-000000000099", "absent", "fixture", 0)))).outcome, "user_missing");
  for (const role of ["anon", "authenticated"]) {
    await denied(`BEGIN; SET LOCAL ROLE ${role}; ${rpc(ids[1], "foreign", "fixture", 0)}; COMMIT;`);
    await denied(`BEGIN; SET LOCAL ROLE ${role}; INSERT INTO public.vault_blobs(user_id,project_id,encrypted_blob) VALUES ('${ids[0]}','bypass','fixture'); COMMIT;`);
  }
  const read = await query(`BEGIN; SET LOCAL ROLE authenticated; SELECT set_config('request.jwt.claims','{"sub":"${ids[0]}","role":"authenticated"}',true); SELECT count(*) FROM public.vault_blobs; SELECT count(*) FROM public.vault_blobs WHERE user_id='${ids[1]}'; COMMIT;`);
  assert.deepEqual(read.split("\n").slice(-2), ["1", "0"]);
  await denied(`BEGIN; SET LOCAL ROLE authenticated; UPDATE public.users SET plan='pro' WHERE id='${ids[1]}'; COMMIT;`);
  await denied(`BEGIN; SET LOCAL ROLE authenticated; UPDATE public.vault_blobs SET encrypted_blob='bypass' WHERE user_id='${ids[1]}'; COMMIT;`);
  await assert.rejects(query(asService(`SELECT * FROM public.push_personal_vault('${ids[1]}','same',repeat('x',1000001),2)`)), (error) => /invalid personal vault push/.test(error.stderr ?? ""));
  assert.equal(await query(`SELECT version FROM public.vault_blobs WHERE user_id='${ids[1]}' AND project_id='same'`), "2");
  console.log("PASS: deterministic two-session quota/CAS, legacy plans and backups, service grants, role denial and cross-account RLS");
} finally {
  if (fixturesCreated) {
    await query(`BEGIN; DROP TRIGGER ${trigger} ON public.vault_blobs; DROP SCHEMA ${schema} CASCADE; DELETE FROM auth.users WHERE id IN ('${ids.join("','")}'); COMMIT;`);
    assert.equal(await query("SELECT (SELECT count(*) FROM public.users) + (SELECT count(*) FROM public.vault_blobs) + (SELECT count(*) FROM auth.users)"), "0");
    console.log("Local vault fixtures and barrier removed");
  }
}
