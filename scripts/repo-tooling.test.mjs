import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import {
  checkCoderabbit,
  checkCodecov,
  checkCoverageWiring,
  checkRenovate,
  checkRepoTooling,
  checkSocket,
  checkSonar,
  root,
  yamlGet,
  yamlKeys,
  yamlList,
} from './check-repo-tooling.mjs';

const read = (rel) => readFileSync(join(root, rel), 'utf8');
const renovate = () => JSON.parse(read('renovate.json'));
const has = (problems, re) => problems.some((p) => re.test(p));
const anyDir = () => true;
const noDir = () => false;

test('the tooling configs on main pass every check', () => {
  assert.deepEqual(checkRepoTooling(), []);
});

test('a missing tooling file reports instead of throwing', () => {
  const tmp = mkdtempSync(join(tmpdir(), 'phantom-tooling-'));
  try {
    const problems = checkRepoTooling(tmp, anyDir);
    assert.ok(problems.length >= 7, `expected one problem per config, got ${problems.length}`);
    assert.ok(problems.every((p) => /missing or unreadable/.test(p)), problems.join('\n'));
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test('renovate.json keeps no-automerge, release-age, and grouping invariants', () => {
  assert.deepEqual(checkRenovate(read('renovate.json')), []);
  assert.ok(has(checkRenovate('{not json'), /invalid JSON/));
  const cases = [
    [(c) => { c.automerge = true; }, /automerge must stay false/],
    [(c) => { c.automerge = 'no'; }, /automerge must stay false/],
    [(c) => { delete c.minimumReleaseAge; }, /minimumReleaseAge/],
    [(c) => { c.vulnerabilityAlerts.enabled = false; }, /vulnerabilityAlerts/],
    [(c) => { c.vulnerabilityAlerts.automerge = true; }, /vulnerabilityAlerts/],
    [(c) => { delete c.schedule; }, /schedule/],
    [(c) => { c.prConcurrentLimit = 0; }, /prConcurrentLimit/],
    [(c) => { c.packageRules.find((r) => r.matchUpdateTypes?.includes('major')).groupName = 'all'; },
      /major updates must stay ungrouped/],
    [(c) => { for (const r of c.packageRules) delete r.groupName; }, /non-major updates must stay grouped/],
    [(c) => { c.packageRules = []; }, /major updates must stay ungrouped/],
    [(c) => { c.packageRules[0].automerge = true; }, /no packageRule may enable automerge/],
  ];
  for (const [mutate, re] of cases) {
    const cfg = renovate();
    mutate(cfg);
    assert.ok(has(checkRenovate(JSON.stringify(cfg)), re), re.source);
  }
});

test('socket.yml keeps version 2 and the fixtures ignore', () => {
  const base = read('socket.yml');
  assert.deepEqual(checkSocket(base), []);
  assert.ok(has(checkSocket(base.replace('version: 2', 'version: 3')), /version must be 2/));
  assert.ok(has(checkSocket(base.replace('  - "**/fixtures/**"\n', '')), /projectIgnorePaths/));
  assert.ok(has(checkSocket(base.replace('didYouMean: true', 'didYouMean: maybe')), /issueRules/));
  assert.ok(has(checkSocket(base.replace('issueRules:', 'rules:')), /issueRules/));
});

test('codecov.yml keeps comments off and statuses informational', () => {
  const base = read('codecov.yml');
  assert.deepEqual(checkCodecov(base), []);
  assert.ok(has(checkCodecov(base.replace('comment: false', 'comment: true')), /comment must stay false/));
  const noInfo = checkCodecov(base.replace(/informational: true/g, 'informational: false'));
  assert.equal(noInfo.filter((p) => /informational must stay true/.test(p)).length, 2, noInfo.join('\n'));
  assert.ok(has(checkCodecov(base.replace('patch:', 'pr_patch:')), /patch.*informational/));
});

test('.coderabbit.yaml keeps the assertive, draft-skipping, quiet profile', () => {
  const base = read('.coderabbit.yaml');
  assert.deepEqual(checkCoderabbit(base, anyDir), []);
  assert.ok(has(checkCoderabbit(base.replace('profile: assertive', 'profile: chill'), anyDir), /profile/));
  assert.ok(has(checkCoderabbit(base.replace('poem: false', 'poem: true'), anyDir), /poem/));
  assert.ok(has(checkCoderabbit(base.replace('drafts: false', 'drafts: true'), anyDir), /drafts/));
  assert.ok(has(checkCoderabbit(base.replace('auto_reply: false', 'auto_reply: true'), anyDir), /auto_reply/));
  assert.ok(has(checkCoderabbit(base.replace('    - "!**/Cargo.lock"\n', ''), anyDir), /Cargo\.lock/));
  assert.ok(
    has(checkCoderabbit(base.replace('    - path: "crates/phantom-vault/**"', '    - path: "crates/phantom-leaks/**"'), anyDir),
      /phantom-vault\/\*\*/),
  );
});

test('.coderabbit.yaml path_instructions targets must exist on disk', () => {
  const mini = `language: en-US
reviews:
  profile: assertive
  high_level_summary: true
  poem: false
  auto_review:
    enabled: true
    drafts: false
  path_filters:
    - "!**/Cargo.lock"
    - "!**/package-lock.json"
    - "!**/target/**"
  path_instructions:
    - path: "crates/phantom-vault/**"
      instructions: |
        High scrutiny.
    - path: "crates/phantom-core/**"
      instructions: |
        High scrutiny.
    - path: "crates/phantom-proxy/**"
      instructions: |
        High scrutiny.
    - path: "crates/phantom-cli/**"
      instructions: |
        High scrutiny.
    - path: "crates/phantom-mcp/**"
      instructions: |
        High scrutiny.
    - path: "apps/web/src/app/api/**"
      instructions: |
        High scrutiny.
chat:
  auto_reply: false
`;
  assert.deepEqual(checkCoderabbit(mini, anyDir), []);
  const missing = checkCoderabbit(mini, noDir);
  assert.equal(missing.filter((p) => /does not exist/.test(p)).length, 6, missing.join('\n'));
});

test('.sonarcloud.properties paths must exist and stay test/source disjoint', () => {
  const base = read('.sonarcloud.properties');
  assert.deepEqual(checkSonar(base, anyDir), []);
  assert.ok(has(checkSonar(base.replace('sonar.organization=ashlrai', 'sonar.organization=other'), anyDir), /organization/));
  const allMissing = checkSonar(base, noDir).filter((p) => /stale analysis path/.test(p));
  assert.ok(allMissing.length >= 10, `expected every listed path flagged, got ${allMissing.length}`);
  assert.ok(
    has(
      checkSonar(base.replace(',apps/web/tests/**', ''), anyDir),
      /apps\/web\/tests must also sit in sonar\.exclusions/,
    ),
  );
  assert.ok(
    has(
      checkSonar(base.replace('sonar.sources=', 'sonar.sources=apps/web/tests,'), anyDir),
      /both a source and a test/,
    ),
  );
});

test('scorecard stays weekly-and-dispatch with read-only permissions and pinned actions', () => {
  const ci = read('.github/workflows/ci.yml');
  const scorecard = read('.github/workflows/scorecard.yml');
  assert.deepEqual(checkCoverageWiring(ci, scorecard), []);
  const withPush = scorecard.replace('on:\n', 'on:\n  pull_request:\n');
  assert.ok(has(checkCoverageWiring(ci, withPush), /unexpected trigger pull_request/));
  const writePerms = scorecard.replace('permissions:\n  contents: read', 'permissions:\n  contents: write');
  assert.ok(has(checkCoverageWiring(ci, writePerms), /contents: read/));
  const floating = scorecard.replace(/ossf\/scorecard-action@[0-9a-f]{40}/, 'ossf/scorecard-action@v2.5.0');
  assert.ok(has(checkCoverageWiring(ci, floating), /not pinned to a full commit SHA/));
});

test('coverage stays out of pull requests and out of the CI Gate', () => {
  const ci = read('.github/workflows/ci.yml');
  const scorecard = read('.github/workflows/scorecard.yml');
  const onPr = ci.replace(/github\.event_name == 'merge_group' \|\| github\.event_name == 'schedule'/g,
    "github.event_name == 'pull_request'");
  assert.ok(has(checkCoverageWiring(onPr, scorecard), /must not run on pull_request/));
  const gated = ci.replace(/docs-commands]/, 'docs-commands, coverage]');
  assert.ok(has(checkCoverageWiring(gated, scorecard), /outside the CI Gate/));
  const noOidc = ci.replace('      id-token: write', '      id-token: read');
  assert.ok(has(checkCoverageWiring(noOidc, scorecard), /id-token: write/));
  const floatingCodecov = ci.replace(/codecov\/codecov-action@[0-9a-f]{40}/, 'codecov/codecov-action@v7');
  const codecovProblems = checkCoverageWiring(floatingCodecov, scorecard);
  assert.ok(has(codecovProblems, /exactly one codecov-action step/));
  assert.ok(has(codecovProblems, /not pinned to a full commit SHA/));
});

test('yaml helpers read only the documented subset', () => {
  const doc = `top:
  nested:
    value: "quoted"
    flag: true
  list:
    - one
    - "two"
    - key: val
  flow: [a, 'b', "c"]
  blocked: |
    literal
other: x
`;
  assert.equal(yamlGet(doc, ['top', 'nested', 'value']), 'quoted');
  assert.equal(yamlGet(doc, ['top', 'nested', 'flag']), 'true');
  assert.equal(yamlGet(doc, ['top', 'nested']), undefined);
  assert.equal(yamlGet(doc, ['top', 'missing']), undefined);
  assert.equal(yamlGet(doc, ['top', 'blocked']), '');
  assert.deepEqual(yamlList(doc, ['top', 'list']), ['one', 'two', 'key: val']);
  assert.deepEqual(yamlList(doc, ['top', 'flow']), ['a', 'b', 'c']);
  assert.deepEqual(yamlList(doc, ['top', 'nested']), undefined);
  assert.deepEqual(yamlKeys(doc, ['top']), ['nested', 'list', 'flow', 'blocked']);
});
