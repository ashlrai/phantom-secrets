// Validate the repository-tooling configs the Scorecard/Codecov/Renovate/
// Sonar/CodeRabbit/Socket rollout added. Each check returns a list of
// problems; an empty list is a pass. Run directly to gate a local check:
//   node scripts/check-repo-tooling.mjs
// exits 1 and prints one problem per line when any config drifts.
//
// The YAML reader below intentionally covers only the subset these files
// use: nested block maps, `- ` lists (scalar items or `- key: value` map
// starts), flow lists `[a, b]`, `|`/`>` block scalars, and comments. A
// construct outside that subset reads as missing rather than mis-parsed.

import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');

function toLines(text) {
  return text.replace(/\r\n/g, '\n').split('\n');
}
function indentOf(line) {
  return line.match(/^ */)[0].length;
}
function contentLines(lines) {
  return lines.filter((l) => l.trim() && !l.trimStart().startsWith('#'));
}
function escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
function stripInlineComment(value) {
  return (value ?? '').replace(/[ \t]+#.*$/, '').trim();
}
function unquote(s) {
  return s.length >= 2 && s[0] === s[s.length - 1] && (s[0] === '"' || s[0] === "'")
    ? s.slice(1, -1)
    : s;
}
// Lines nested under the key on `lines[index]` (key sits at `indent`).
function childLines(lines, index, indent) {
  const out = [];
  for (let i = index + 1; i < lines.length; i++) {
    const l = lines[i];
    if (l.trim() && indentOf(l) <= indent) break;
    out.push(l);
  }
  return out;
}
function findKey(lines, key) {
  let base = Infinity;
  for (const l of lines) {
    if (!l.trim() || l.trimStart().startsWith('#')) continue;
    const ind = indentOf(l);
    if (ind < base) base = ind;
  }
  if (base === Infinity) return null;
  const re = new RegExp(`^ {${base}}${escapeRe(key)}:(?:[ \\t]+(.*))?$`);
  for (let i = 0; i < lines.length; i++) {
    if (indentOf(lines[i]) !== base) continue;
    const m = lines[i].match(re);
    if (m) return { index: i, indent: base, inline: stripInlineComment(m[1]) };
  }
  return null;
}
// Scalar value at a nested `key: value` path, or undefined when the path is
// absent or holds a map/list. Block scalars return ''.
export function yamlGet(text, path) {
  let lines = toLines(text);
  for (let i = 0; i < path.length; i++) {
    const hit = findKey(lines, path[i]);
    if (!hit) return undefined;
    if (i === path.length - 1) {
      if (hit.inline === '') return undefined;
      if (/^[|>]/.test(hit.inline)) return '';
      return unquote(hit.inline);
    }
    if (hit.inline !== '') return undefined;
    lines = childLines(lines, hit.index, hit.indent);
  }
}
// Raw lines of the block under a nested key path (map content or list body),
// joined back into text. Undefined when the path is absent.
export function yamlBlock(text, path) {
  let lines = toLines(text);
  for (const key of path) {
    const hit = findKey(lines, key);
    if (!hit) return undefined;
    lines = childLines(lines, hit.index, hit.indent);
  }
  return lines.join('\n');
}
// Direct child keys of the map at a nested path.
export function yamlKeys(text, path) {
  const block = yamlBlock(text, path);
  if (block === undefined) return [];
  const lines = contentLines(toLines(block));
  const base = Math.min(...lines.map(indentOf));
  const keys = [];
  for (const l of lines) {
    if (indentOf(l) !== base) continue;
    const m = l.match(/^ *([\w-]+):/);
    if (m) keys.push(m[1]);
  }
  return keys;
}
function flowList(inline) {
  const t = inline.trim();
  if (!t.startsWith('[') || !t.endsWith(']')) return null;
  const inner = t.slice(1, -1).trim();
  return inner ? inner.split(',').map((s) => unquote(s.trim())) : [];
}
// List items at a nested key: `- item` entries (raw item text, so `- k: v`
// map starts keep `k: v`) or a flow `[a, b]` value. Undefined when absent.
export function yamlList(text, path) {
  const parent = path.slice(0, -1);
  const scope = parent.length ? yamlBlock(text, parent) : text;
  if (scope === undefined) return undefined;
  const lines = toLines(scope);
  const hit = findKey(lines, path[path.length - 1]);
  if (!hit) return undefined;
  if (hit.inline !== '') return flowList(hit.inline) ?? undefined;
  const items = [];
  for (const l of contentLines(childLines(lines, hit.index, hit.indent))) {
    const m = l.match(/^\s*-\s+(.*)$/);
    // unquote only affects fully quoted scalars; `- key: "v"` map starts
    // keep their raw text for the caller.
    if (m) items.push(unquote(stripInlineComment(m[1])));
  }
  return items.length ? items : undefined;
}

function asArray(v) {
  return Array.isArray(v) ? v : [];
}
const pathExistsIn = (rootDir) => (rel) => existsSync(join(rootDir, rel));

export function checkRenovate(text) {
  const problems = [];
  let cfg;
  try {
    cfg = JSON.parse(text);
  } catch (err) {
    return [`renovate.json: invalid JSON (${err.message})`];
  }
  if (!Array.isArray(cfg.extends) || !cfg.extends.length || !cfg.extends.every((s) => typeof s === 'string' && s)) {
    problems.push('renovate.json: extends must be a non-empty string array');
  }
  if (cfg.automerge !== false) problems.push('renovate.json: automerge must stay false (no unreviewed merges)');
  if (typeof cfg.minimumReleaseAge !== 'string' || !cfg.minimumReleaseAge) {
    problems.push('renovate.json: minimumReleaseAge must be a non-empty duration');
  }
  if (cfg.vulnerabilityAlerts?.enabled !== true || cfg.vulnerabilityAlerts?.automerge !== false) {
    problems.push('renovate.json: vulnerabilityAlerts must stay enabled without automerge');
  }
  if (typeof cfg.timezone !== 'string' || !cfg.timezone) problems.push('renovate.json: timezone must be set');
  if (!Array.isArray(cfg.schedule) || !cfg.schedule.length || !cfg.schedule.every((s) => typeof s === 'string' && s)) {
    problems.push('renovate.json: schedule must be a non-empty string array');
  }
  for (const key of ['prConcurrentLimit', 'prHourlyLimit']) {
    if (!Number.isInteger(cfg[key]) || cfg[key] < 1) problems.push(`renovate.json: ${key} must be a positive integer`);
  }
  const rules = asArray(cfg.packageRules);
  const majorsSolo = rules.some(
    (r) => asArray(r.matchUpdateTypes).includes('major') && r.groupName == null && r.groupSlug == null,
  );
  const nonMajorsGrouped = rules.some((r) => {
    const types = asArray(r.matchUpdateTypes);
    return (types.includes('minor') || types.includes('patch')) && !types.includes('major')
      && typeof r.groupName === 'string' && r.groupName;
  });
  if (!majorsSolo) problems.push('renovate.json: major updates must stay ungrouped (one pull request each)');
  if (!nonMajorsGrouped) problems.push('renovate.json: non-major updates must stay grouped into one pull request');
  if (rules.some((r) => r.automerge === true)) {
    problems.push('renovate.json: no packageRule may enable automerge');
  }
  return problems;
}

export function checkSocket(text) {
  const problems = [];
  const version = yamlGet(text, ['version']);
  if (version !== '2') problems.push(`socket.yml: version must be 2 (found ${version ?? 'nothing'})`);
  const ignores = yamlList(text, ['projectIgnorePaths']);
  if (!ignores || !ignores.includes('**/fixtures/**')) {
    problems.push('socket.yml: projectIgnorePaths must exclude **/fixtures/**');
  }
  const rulesBlock = yamlBlock(text, ['issueRules']);
  if (rulesBlock === undefined) {
    problems.push('socket.yml: issueRules block missing');
  } else {
    const entries = contentLines(toLines(rulesBlock));
    if (!entries.length || entries.some((l) => !/^ *[\w-]+:\s*(true|false)\s*$/.test(l))) {
      problems.push('socket.yml: every issueRules entry must be `name: true|false`');
    }
  }
  return problems;
}

export function checkCodecov(text) {
  const problems = [];
  if (yamlGet(text, ['comment']) !== 'false') problems.push('codecov.yml: comment must stay false');
  for (const scope of ['project', 'patch']) {
    if (yamlGet(text, ['coverage', 'status', scope, 'default', 'informational']) !== 'true') {
      problems.push(`codecov.yml: coverage.status.${scope}.default.informational must stay true`);
    }
  }
  return problems;
}

// Directories whose code paths CodeRabbit must keep high-scrutiny
// instructions for. Derived from the Tier-1 ownership list.
const CODERABBIT_SCRUTINY = [
  'crates/phantom-vault',
  'crates/phantom-core',
  'crates/phantom-proxy',
  'crates/phantom-cli',
  'crates/phantom-mcp',
  'apps/web/src/app/api',
];

export function checkCoderabbit(text, exists = pathExistsIn(root)) {
  const problems = [];
  const expect = (path, want, label) => {
    if (yamlGet(text, path) !== want) problems.push(`.coderabbit.yaml: ${label}`);
  };
  expect(['language'], 'en-US', 'language must stay en-US');
  expect(['reviews', 'profile'], 'assertive', 'reviews.profile must stay assertive');
  expect(['reviews', 'high_level_summary'], 'true', 'reviews.high_level_summary must stay on');
  expect(['reviews', 'poem'], 'false', 'reviews.poem must stay off');
  expect(['reviews', 'auto_review', 'enabled'], 'true', 'reviews.auto_review must stay enabled');
  expect(['reviews', 'auto_review', 'drafts'], 'false', 'reviews.auto_review must skip drafts');
  expect(['chat', 'auto_reply'], 'false', 'chat.auto_reply must stay off');
  const filters = yamlList(text, ['reviews', 'path_filters']) ?? [];
  for (const required of ['!**/Cargo.lock', '!**/package-lock.json', '!**/target/**']) {
    if (!filters.includes(required)) problems.push(`.coderabbit.yaml: path_filters must exclude ${required}`);
  }
  const items = yamlList(text, ['reviews', 'path_instructions']) ?? [];
  const covered = items
    .map((i) => (i.match(/^path:\s*(.+)$/)?.[1] ?? '').trim())
    .map(unquote)
    .filter(Boolean);
  for (const dir of CODERABBIT_SCRUTINY) {
    if (!covered.includes(`${dir}/**`)) problems.push(`.coderabbit.yaml: path_instructions must cover ${dir}/**`);
  }
  for (const pattern of covered) {
    if (pattern.endsWith('/**') && !exists(pattern.slice(0, -3))) {
      problems.push(`.coderabbit.yaml: path_instructions target ${pattern} does not exist`);
    }
  }
  return problems;
}

export function checkSonar(text, exists = pathExistsIn(root)) {
  const problems = [];
  const props = {};
  for (const raw of toLines(text)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq === -1) {
      problems.push(`.sonarcloud.properties: malformed line ${JSON.stringify(line)}`);
      continue;
    }
    props[line.slice(0, eq).trim()] = line.slice(eq + 1).trim();
  }
  if (props['sonar.organization'] !== 'ashlrai') {
    problems.push('.sonarcloud.properties: sonar.organization must stay ashlrai');
  }
  if (props['sonar.projectKey'] !== 'ashlrai_phantom-secrets') {
    problems.push('.sonarcloud.properties: sonar.projectKey must stay ashlrai_phantom-secrets');
  }
  const listed = (key) => (props[key] ?? '').split(',').map((s) => s.trim()).filter(Boolean);
  const sources = listed('sonar.sources');
  const tests = listed('sonar.tests');
  const exclusions = new Set(listed('sonar.exclusions'));
  for (const rel of [...sources, ...tests]) {
    if (!exists(rel)) problems.push(`.sonarcloud.properties: ${rel} does not exist (stale analysis path)`);
  }
  for (const rel of tests) {
    if (sources.includes(rel)) {
      problems.push(`.sonarcloud.properties: ${rel} is listed as both a source and a test`);
    } else if (!exclusions.has(rel) && !exclusions.has(`${rel}/**`)) {
      problems.push(`.sonarcloud.properties: test path ${rel} must also sit in sonar.exclusions`);
    }
  }
  return problems;
}

const SHA_PIN = /@[0-9a-f]{40}$/;

export function checkCoverageWiring(ciText, scorecardText) {
  const problems = [];
  const triggers = yamlKeys(scorecardText, ['on']);
  if (!triggers.length) {
    problems.push('scorecard.yml: on: block missing or unreadable');
  } else {
    for (const t of triggers) {
      if (t !== 'schedule' && t !== 'workflow_dispatch') {
        problems.push(`scorecard.yml: unexpected trigger ${t} (weekly schedule + dispatch only)`);
      }
    }
    if (!triggers.includes('schedule')) problems.push('scorecard.yml: schedule trigger missing');
  }
  if (yamlGet(scorecardText, ['permissions', 'contents']) !== 'read') {
    problems.push('scorecard.yml: top-level permissions must be contents: read');
  }
  for (const m of scorecardText.matchAll(/uses:\s*([^\s#]+)/g)) {
    if (!SHA_PIN.test(m[1])) problems.push(`scorecard.yml: action ${m[1]} is not pinned to a full commit SHA`);
  }
  if (!scorecardText.includes('results.sarif')) problems.push('scorecard.yml: results.sarif upload wiring missing');
  const condition = yamlGet(ciText, ['jobs', 'coverage', 'if']);
  if (condition === undefined) {
    problems.push('ci.yml: coverage job missing');
  } else {
    if (!condition.includes('merge_group') || !condition.includes('schedule')) {
      problems.push('ci.yml: coverage job must run only on merge_group and the nightly schedule');
    }
    if (/pull_request|\bpush\b/.test(condition)) {
      problems.push('ci.yml: coverage job must not run on pull_request or push');
    }
  }
  if (yamlGet(ciText, ['jobs', 'coverage', 'permissions', 'id-token']) !== 'write') {
    problems.push('ci.yml: coverage job needs id-token: write for the Codecov OIDC upload');
  }
  const gateNeeds = yamlList(ciText, ['jobs', 'gate', 'needs']);
  if (!gateNeeds) {
    problems.push('ci.yml: gate job needs list unreadable');
  } else if (gateNeeds.includes('coverage')) {
    problems.push('ci.yml: coverage must stay outside the CI Gate needs list');
  }
  const codecovSteps = ciText.match(/uses:\s*codecov\/codecov-action@[0-9a-f]{40}/g) ?? [];
  if (codecovSteps.length !== 1) {
    problems.push('ci.yml: expected exactly one codecov-action step pinned to a full commit SHA');
  }
  for (const m of ciText.matchAll(/uses:\s*([^\s#]+)/g)) {
    if (!SHA_PIN.test(m[1])) problems.push(`ci.yml: action ${m[1]} is not pinned to a full commit SHA`);
  }
  return problems;
}

export function checkRepoTooling(rootDir = root, exists = pathExistsIn(rootDir)) {
  const problems = [];
  const read = (rel) => {
    try {
      return readFileSync(join(rootDir, rel), 'utf8');
    } catch {
      problems.push(`${rel}: missing or unreadable`);
      return undefined;
    }
  };
  const renovate = read('renovate.json');
  if (renovate !== undefined) problems.push(...checkRenovate(renovate));
  const socket = read('socket.yml');
  if (socket !== undefined) problems.push(...checkSocket(socket));
  const codecov = read('codecov.yml');
  if (codecov !== undefined) problems.push(...checkCodecov(codecov));
  const coderabbit = read('.coderabbit.yaml');
  if (coderabbit !== undefined) problems.push(...checkCoderabbit(coderabbit, exists));
  const sonar = read('.sonarcloud.properties');
  if (sonar !== undefined) problems.push(...checkSonar(sonar, exists));
  const ci = read('.github/workflows/ci.yml');
  const scorecard = read('.github/workflows/scorecard.yml');
  if (ci !== undefined && scorecard !== undefined) {
    problems.push(...checkCoverageWiring(ci, scorecard));
  }
  return problems;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const problems = checkRepoTooling();
  if (problems.length) {
    for (const p of problems) console.error(p);
    process.exit(1);
  }
  console.log('repo tooling configs OK');
}
