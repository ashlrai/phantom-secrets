const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");
const React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");

const filename = path.resolve(__dirname, "../src/app/dashboard/overview-client.tsx");
const profile = { github_login: "synthetic-owner", email: "owner@example.invalid" };
const result = (data, overrides = {}) => ({ data, error: null, loading: false, ...overrides });

function renderOverview(user = result(profile), vaults = result([])) {
  const queries = [];
  const compiled = ts.transpileModule(fs.readFileSync(filename, "utf8"), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, target: ts.ScriptTarget.ES2022 },
    fileName: filename,
  }).outputText;
  const module = { exports: {} };
  new Function("require", "module", "exports", compiled)((name) => {
    if (name === "@/lib/use-supabase-query") return {
      useSupabaseQuery(build) {
        let table;
        build({ from(name) {
          table = name;
          const query = { table, columns: null, maybeSingle: false };
          queries.push(query);
          return {
            select(columns) { query.columns = columns; return this; },
            maybeSingle() { query.maybeSingle = true; return this; },
            // Only for the original-component causal control. Null/no-error is
            // the hooked result; the test below independently checks zero-row
            // query semantics use maybeSingle, never single.
            single() { return this; },
            order() { return this; },
          };
        } });
        assert.ok(["users", "vault_blobs"].includes(table));
        return table === "users" ? user : vaults;
      },
    };
    return require(name);
  }, module, module.exports);
  return { html: renderToStaticMarkup(React.createElement(module.exports.default)), queries };
}

test("finished missing-profile query shows trusted-terminal onboarding without inventing a backup", () => {
  const { html, queries } = renderOverview(result(null));
  assert.equal(queries.find((query) => query.table === "users").maybeSingle, true);
  assert.match(html, /Connect Phantom Secrets/);
  assert.match(html, /trusted terminal/);
  assert.match(html, /phantom login/);
  assert.match(html, /device approval/);
  assert.match(html, /phantom cloud push/);
  assert.match(html, /Reload this dashboard/);
  assert.match(html, /original OS keychain/);
  assert.match(html, /Signing in on another machine cannot transfer or recover that key/);
  assert.doesNotMatch(html, /Loading your data|Backed-up projects|Encrypted data|<table/);
  assert.deepEqual(queries.map(({ table, columns }) => ({ table, columns })), [
    { table: "users", columns: "github_login, email" },
    { table: "vault_blobs", columns: "project_id, version, updated_at, encrypted_blob" },
  ]);
});

for (const loadingTable of ["users", "vault_blobs"]) {
  test(`${loadingTable} loading does not flash missing-profile onboarding`, () => {
    const { html } = renderOverview(
      result(null, { loading: loadingTable === "users" }),
      result(null, { loading: loadingTable === "vault_blobs" }),
    );
    assert.match(html, /Loading your data/);
    assert.match(html, /role="status"/);
    assert.doesNotMatch(html, /Connect Phantom Secrets|phantom login|Backed-up projects/);
  });
}

for (const failingTable of ["users", "vault_blobs"]) {
  test(`${failingTable} database errors are safe failure, never first-use or empty-backup claims`, () => {
    const error = "synthetic-private-database-detail";
    const { html } = renderOverview(
      result(null, { error: failingTable === "users" ? error : null }),
      result([], { error: failingTable === "vault_blobs" ? error : null }),
    );
    assert.match(html, /Unable to load your account or backup metadata/);
    assert.match(html, /Reload this page/);
    assert.match(html, /role="alert"/);
    assert.doesNotMatch(html, /synthetic-private|Connect Phantom Secrets|No cloud backup yet|Backed-up projects/);
  });
}

test("registered account with zero backups preserves genuine empty-backup guidance", () => {
  const { html } = renderOverview();
  assert.match(html, /No cloud backup yet/);
  assert.match(html, /phantom cloud push/);
  assert.match(html, /original keychain/);
  assert.match(html, /Backed-up projects/);
  assert.doesNotMatch(html, /Connect Phantom Secrets|phantom login|Unable to load/);
});

test("existing encrypted backup keeps project/version/link and never renders ciphertext", () => {
  const { html } = renderOverview(result(profile), result([{
    project_id: "synthetic-project", version: 7, updated_at: "2026-10-01T00:00:00.000Z",
    encrypted_blob: "synthetic-private-ciphertext",
  }]));
  assert.match(html, /synthetic-project/);
  assert.match(html, /v7/);
  assert.match(html, /href="\/dashboard\/projects\/synthetic-project"/);
  assert.match(html, /Your projects/);
  assert.doesNotMatch(html, /synthetic-private-ciphertext|Connect Phantom Secrets|No cloud backup yet|Unable to load/);
});

test("a settled null vault result is a safe failure, not endless loading or an invented empty backup", () => {
  const { html } = renderOverview(result(profile), result(null));
  assert.match(html, /Unable to load your account or backup metadata/);
  assert.doesNotMatch(html, /Loading your data|No cloud backup yet|Connect Phantom Secrets/);
});
