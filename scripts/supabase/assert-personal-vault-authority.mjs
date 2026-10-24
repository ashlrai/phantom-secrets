#!/usr/bin/env node
// Run only against the empty, replayed local CI database. Separate psql sessions
// and a held advisory barrier make quota/CAS overlap deterministic, not timing-based.
import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { randomBytes, randomInt } from "node:crypto";
import { promisify } from "node:util";
import { readFile } from "node:fs/promises";

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

// Effective privileges include inherited role and PUBLIC grants. A fresh replay
// alone misses the hosted project's legacy broad ACLs, so reproduce them and
// reapply the exact additive migration before exercising the real RPC/RLS paths.
const browserTables = ["users", "vault_blobs", "device_tokens", "teams", "team_members", "team_vault_blobs", "team_key_shares", "platform_tokens", "stripe_processed_events", "stripe_subscription_users", "device_auth_rate_limits"];
const browserReadTables = new Set(["users", "vault_blobs", "teams", "team_members", "team_vault_blobs"]);
const tablePrivileges = ["SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER", "MAINTAIN"];
async function assertBrowserAuthority() {
  for (const role of ["anon", "authenticated"]) {
    for (const table of browserTables) {
      const allowed = role === "authenticated" && browserReadTables.has(table);
      const result = JSON.parse(await query(`SELECT json_agg(has_table_privilege('${role}','public.${table}',privilege) ORDER BY ord) FROM unnest(ARRAY['${tablePrivileges.join("','")}']) WITH ORDINALITY AS p(privilege,ord)`));
      assert.deepEqual(result, tablePrivileges.map((privilege) => allowed && privilege === "SELECT"), `${role} effective privileges on ${table}`);
      const columns = await query(`SELECT bool_and(NOT has_column_privilege('${role}',a.attrelid,a.attnum,p.privilege)) FROM pg_attribute a CROSS JOIN (VALUES ('INSERT'),('UPDATE'),('REFERENCES')) p(privilege) WHERE a.attrelid='public.${table}'::regclass AND a.attnum>0 AND NOT a.attisdropped`);
      assert.equal(columns, "t", `${role} column writes on ${table}`);
      if (!allowed) assert.equal(await query(`SELECT bool_and(NOT has_column_privilege('${role}',a.attrelid,a.attnum,'SELECT')) FROM pg_attribute a WHERE a.attrelid='public.${table}'::regclass AND a.attnum>0 AND NOT a.attisdropped`), "t", `${role} column reads on ${table}`);
    }
  }
}
assert.equal(await query("SELECT count(*) FROM supabase_migrations.schema_migrations WHERE version='20261009231437'"), "1");
await assertBrowserAuthority();
const serviceAclSql = `SELECT json_agg(json_build_object('table',c.relname,'privilege',a.privilege_type,'grantable',a.is_grantable) ORDER BY c.relname,a.privilege_type,a.is_grantable) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a WHERE n.nspname='public' AND c.relname IN ('${browserTables.join("','")}') AND a.grantee='service_role'::regrole`;
const originalServiceAcl = await query(serviceAclSql);
const functionAuthoritySql = "SELECT json_agg(json_build_object('schema',n.nspname,'name',p.proname,'arguments',pg_get_function_identity_arguments(p.oid),'definer',p.prosecdef,'config',p.proconfig,'acl',p.proacl) ORDER BY n.nspname,p.proname,pg_get_function_identity_arguments(p.oid)) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname IN ('public','app_private') AND p.prokind='f'";
const originalFunctionAuthority = await query(functionAuthoritySql);
const clampMigration = await readFile(new URL("../../apps/web/supabase/migrations/20261009231437_clamp_browser_table_authority.sql", import.meta.url), "utf8");
// Seed only ACLs on this admitted empty local fixture. The candidate must remove
// PUBLIC inheritance as well as grants directly attached to both browser roles.
await query(`BEGIN; GRANT ALL PRIVILEGES ON TABLE ${browserTables.map((table) => `public.${table}`).join(",")} TO PUBLIC, anon, authenticated; GRANT SELECT(github_login) ON public.users TO anon; GRANT UPDATE(encrypted_blob) ON public.vault_blobs TO authenticated; ${clampMigration} COMMIT;`);
await assertBrowserAuthority();
assert.equal(await query(serviceAclSql), originalServiceAcl, "service-role ACL must be unchanged");
assert.equal(await query(functionAuthoritySql), originalFunctionAuthority, "RPC and membership-helper authority must be unchanged");

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
  // Membership-backed reads remain available without widening visibility.
  const teamIds = ["20000000-0000-4000-8000-000000000001", "20000000-0000-4000-8000-000000000002"];
  await query(`BEGIN;
    INSERT INTO public.teams(id,name,owner_id) VALUES ('${teamIds[0]}','fixture-team-a','${ids[0]}'),('${teamIds[1]}','fixture-team-b','${ids[1]}');
    INSERT INTO public.team_members(team_id,user_id,role) VALUES ('${teamIds[0]}','${ids[0]}','owner'),('${teamIds[1]}','${ids[1]}','owner');
    INSERT INTO public.team_vault_blobs(team_id,project_id,encrypted_blob) VALUES ('${teamIds[0]}','fixture','cipher-a'),('${teamIds[1]}','fixture','cipher-b');
    COMMIT;`);
  for (const table of ["users", "teams", "team_members", "team_vault_blobs"]) {
    const visible = await query(`BEGIN; SET LOCAL ROLE authenticated; SELECT set_config('request.jwt.claims','{"sub":"${ids[0]}","role":"authenticated"}',true); SELECT count(*) FROM public.${table}; COMMIT;`);
    assert.equal(visible.split("\n").at(-1), "1", `${table} own account/team read remains isolated`);
  }
  for (const role of ["anon", "authenticated"]) {
    // TRUNCATE is specifically outside RLS; denial must come from table ACLs.
    await denied(`BEGIN; SET LOCAL ROLE ${role}; TRUNCATE public.vault_blobs; COMMIT;`);
    for (const table of ["device_tokens", "platform_tokens", "team_key_shares", "stripe_processed_events", "stripe_subscription_users", "device_auth_rate_limits"]) {
      await denied(`BEGIN; SET LOCAL ROLE ${role}; SELECT * FROM public.${table}; COMMIT;`);
    }
  }
  const read = await query(`BEGIN; SET LOCAL ROLE authenticated; SELECT set_config('request.jwt.claims','{"sub":"${ids[0]}","role":"authenticated"}',true); SELECT count(*) FROM public.vault_blobs; SELECT count(*) FROM public.vault_blobs WHERE user_id='${ids[1]}'; COMMIT;`);
  assert.deepEqual(read.split("\n").slice(-2), ["1", "0"]);
  await denied(`BEGIN; SET LOCAL ROLE authenticated; UPDATE public.users SET plan='pro' WHERE id='${ids[1]}'; COMMIT;`);
  await denied(`BEGIN; SET LOCAL ROLE authenticated; UPDATE public.vault_blobs SET encrypted_blob='bypass' WHERE user_id='${ids[1]}'; COMMIT;`);
  await assert.rejects(query(asService(`SELECT * FROM public.push_personal_vault('${ids[1]}','same',repeat('x',1000001),2)`)), (error) => /invalid personal vault push/.test(error.stderr ?? ""));
  assert.equal(await query(`SELECT version FROM public.vault_blobs WHERE user_id='${ids[1]}' AND project_id='same'`), "2");
  console.log("PASS: deterministic two-session quota/CAS, legacy plans and backups, service grants, legacy ACL clamp, role denial and account/team RLS");
} finally {
  if (fixturesCreated) {
    await query(`BEGIN; DROP TRIGGER ${trigger} ON public.vault_blobs; DROP SCHEMA ${schema} CASCADE; DELETE FROM auth.users WHERE id IN ('${ids.join("','")}'); COMMIT;`);
    assert.equal(await query("SELECT (SELECT count(*) FROM public.users) + (SELECT count(*) FROM public.vault_blobs) + (SELECT count(*) FROM auth.users)"), "0");
    console.log("Local vault fixtures and barrier removed");
  }
}
