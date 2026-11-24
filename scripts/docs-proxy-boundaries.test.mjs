import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const read = path => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
const gettingStarted = read('docs/getting-started.md');
const claude = read('docs/claude-code.md');
const troubleshooting = read('docs/troubleshooting.md');

test('dotenv denial guidance treats mappings as sensitive but never resolvable client input', () => {
  const section = gettingStarted.split('### Claude Code cannot read `.env` after setup')[1]?.split('\n---')[0];
  assert.ok(section, 'missing dotenv denial guidance');
  assert.match(section, /sensitive project metadata/);
  assert.match(section, /Client headers and bodies never\s+resolve mappings/);
  assert.match(section, /matched route's\s+vault value/);
  assert.doesNotMatch(section, /proxy could resolve/);
});

test('mapping rotation is not presented as revoking an active proxy session', () => {
  const row = claude.split('\n').find(line => line.startsWith('| `phantom_rotate` |'));
  assert.ok(row, 'missing MCP rotation guidance');
  assert.match(row, /persistent.*managed dotenv/);
  assert.match(row, /Provider credentials and expiry metadata are unchanged/);
  assert.match(row, /does not revoke.*phantom exec.*proxy bearer/);
  assert.doesNotMatch(row, /cached them will break/);
});

test('runtime and mirrored MCP rotation descriptions preserve the session boundary', () => {
  const source = read('crates/phantom-mcp/src/server.rs');
  const description = source.match(/#\[tool\(\s*description = "([^"]*)"\s*\)\]\s*fn phantom_rotate\(/)?.[1];
  assert.ok(description, 'missing MCP rotation tool description');
  const registry = JSON.parse(read('mcp-registry/server.json'));
  assert.equal(registry.tools.find(tool => tool.name === 'phantom_rotate')?.description, description);
  assert.match(description, /does not revoke.*phantom exec.*proxy bearer/);
  assert.match(description, /Provider credentials and expiry metadata are unchanged/);
  assert.doesNotMatch(description, /cached them will break/);
});

test('rotation confirmation schemas do not promise active-session revocation', () => {
  const params = read('crates/phantom-mcp/src/tools/params.rs');
  const registry = JSON.parse(read('mcp-registry/server.json'));
  for (const [type, name] of [
    ['RotateParams', 'phantom_rotate'],
    ['AutoRotateParams', 'phantom_secrets_auto_rotate'],
  ]) {
    const body = params.split(`pub struct ${type} {`)[1]?.split('\n}')[0];
    assert.ok(body, `missing ${type}`);
    const comment = body.match(/((?:    \/\/\/[^\n]*\n)+)    #\[serde\(default\)\]\n    pub confirm:/)?.[1];
    assert.ok(comment, `missing ${type} confirmation description`);
    const description = comment.trimEnd().split('\n').map(line => line.replace(/^    \/\/\/ ?/, '')).join('\n');
    const schema = registry.tools.find(tool => tool.name === name)?.inputSchema;
    assert.equal(schema?.properties.confirm.description, description);
    assert.match(description.replace(/\s+/g, ' '), /does not revoke a running `phantom exec` session/);
    assert.match(description, /changes no provider credential or lifecycle metadata/);
    assert.doesNotMatch(description, /will break|disrupt running/);
  }
});

test('401 troubleshooting distinguishes a lifecycle lock from listener health', () => {
  const section = troubleshooting.split('### API calls return 401 Unauthorized')[1]?.split('\n### ')[0];
  assert.ok(section, 'missing 401 troubleshooting');
  assert.match(section, /phantom status.*lifecycle lock/);
  assert.match(section, /does not authenticate or identify a listener/);
  assert.match(section, /not a proxy health check/);
  assert.match(section, /phantom exec -- <cmd>/);
  assert.doesNotMatch(section, /Check the proxy is running.*phantom status/);
});

test('doctor guidance separates local diagnostics from the explicit vault probe', () => {
  const section = gettingStarted.split('### `phantom doctor`')[1]?.split('\n### ')[0];
  assert.ok(section, 'missing doctor guidance');
  assert.match(section, /does not open the vault[\s\S]*including with `--fix`/);
  assert.match(section, /phantom agent doctor --json --vault/);
  assert.match(section, /phantom agent doctor --json` alone skips it/);
  assert.doesNotMatch(section, /pass: Vault backend:|pass: \d+ secret\(s\) in vault/);
  const row = claude.split('\n').find(line => line.startsWith('| `phantom_doctor` |'));
  assert.ok(row, 'missing MCP doctor guidance');
  assert.match(row, /Neither this tool nor CLI `phantom doctor` opens the vault/);
  assert.match(row, /phantom agent doctor --json --vault/);
});
