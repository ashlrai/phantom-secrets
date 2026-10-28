import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export const guides = ['README.md', 'AGENTS.md', 'mcp-registry/README.md',
  'docs/README.md', 'docs/getting-started.md',
  'docs/troubleshooting.md', 'docs/public-fact-sheet.md', 'docs/llms.txt',
  'docs/llms-full.txt', 'docs/delegation-quickstart.md', 'docs/ci-cd.md',
  'docs/platform-support.md', 'docs/index.html'];

// Current-tense distribution claims contradicted by the recorded evidence:
// the Homebrew formula was bumped to v0.7.9 (ashlrai/homebrew-phantom#7) and
// npm `latest` is 0.7.9. Dated observations ("was", "recorded", "snapshot")
// stay valid.
const STALE_CLAIM =
  /latest[`\s]*(?:currently resolves|remains|is)\s*`?0\.6\.0|still\s+(?:publishes|at)[\s\S]{0,80}?v?0\.7\.8|formula[\s\S]{0,60}?(?:currently|still)[\s\S]{0,40}?v?0\.7\.8|formula at v?0\.7\.8|still\s+`?v?0\.7\.8`?\s*until\b|not yet been bumped|until (?:the formula|it) is bumped(?! to)|bump.*pending/i;

// Credential shapes the guides must never show even as examples: secrets
// appear by name only (`OPENAI_API_KEY`, `phm_…`, `<TOKEN>` placeholders).
const SECRET_SHAPE =
  /sk-(?:live|test|proj|ant)[-_][a-z0-9_-]{3,}|sk-[a-z0-9_-]{6,}|ghp_[a-z0-9]{6,}|gho_[a-z0-9]{6,}|github_pat_[a-z0-9_]{6,}|xox[baprs]-[a-z0-9-]{4,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY|(?:postgres|mysql|mongodb(?:\+srv)?):\/\/[^\s/@]+:[^\s/@]+@|Bearer\s+[a-zA-Z0-9._-]{12,}/i;

const ECOSYSTEM_LINKS = [
  'https://phm.dev',
  'https://github.com/ashlrai/phantom',
  'https://github.com/ashlrai/locus',
  'https://lexicon.ashlr.ai',
  'https://md.ashlr.ai',
  'https://stack.ashlr.ai',
  'https://plugin.ashlr.ai',
];

// GitHub heading anchors: lowercase, drop characters outside
// [letters, numbers, space, underscore, hyphen], fold spaces to hyphens,
// dedupe repeated slugs with `-1`, `-2`, …
export function githubAnchor(text) {
  return text.trim().toLowerCase()
    .replace(/[^\p{L}\p{N} _-]/gu, '')
    .replace(/ /g, '-');
}

// Anchors a page exposes: markdown heading slugs and explicit <a id/name>
// for .md files; every element id for .html files.
export function pageAnchors(text, file) {
  const anchors = new Set();
  if (/\.html?$/i.test(file)) {
    for (const m of text.matchAll(/\sid="([^"]+)"/g)) anchors.add(m[1]);
    return anchors;
  }
  const seen = new Map();
  for (const line of text.split('\n')) {
    const m = line.match(/^#{1,6}\s+(.*?)\s*#*\s*$/);
    if (m) {
      const base = githubAnchor(m[1]);
      const n = seen.get(base) ?? 0;
      seen.set(base, n + 1);
      anchors.add(n === 0 ? base : `${base}-${n}`);
    }
    for (const a of line.matchAll(/<a\s+(?:id|name)="([^"]+)"/g)) {
      anchors.add(a[1]);
    }
  }
  return anchors;
}

export function checkGuide(text, file, base = root) {
  const errors = [];
  if (file !== 'docs/distribution-status.md' && !text.includes('distribution-status.md')) errors.push(`${file}: missing distribution status link`);
  if (STALE_CLAIM.test(text)) {
    errors.push(`${file}: stale current distribution claim`);
  }
  const ownAnchors = pageAnchors(text, file);
  const targetAnchors = new Map();
  for (const match of text.matchAll(/(?:\[[^\]\n]+\]\(([^)\s]+)\)|href="([^"]+)")/g)) {
    const raw = match[1] ?? match[2];
    const hash = raw.indexOf('#');
    let target = '';
    let fragment = '';
    try {
      target = hash === -1 ? raw : decodeURIComponent(raw.slice(0, hash));
      fragment = hash === -1 ? '' : decodeURIComponent(raw.slice(hash + 1));
    } catch {
      errors.push(`${file}: malformed link ${raw}`);
      continue;
    }
    if (/^[a-z][a-z\d+.-]*:/i.test(target) || target.startsWith('/')) continue;
    if (!target) {
      if (fragment && !ownAnchors.has(fragment)) {
        errors.push(`${file}: missing anchor #${fragment}`);
      }
      continue;
    }
    const resolved = resolve(base, dirname(file), target);
    if (!existsSync(resolved)) {
      errors.push(`${file}: missing local link ${target}`);
      continue;
    }
    if (fragment && /\.(md|markdown|txt|html?)$/i.test(target)) {
      if (!targetAnchors.has(resolved)) {
        targetAnchors.set(resolved, pageAnchors(readFileSync(resolved, 'utf8'), target));
      }
      if (!targetAnchors.get(resolved).has(fragment)) {
        errors.push(`${file}: missing anchor ${target}#${fragment}`);
      }
    }
  }
  return errors;
}

// README-only invariants: examples never show credential-shaped strings and
// the Ashlr ecosystem section lists every sibling once.
export function checkReadmeSurface(text, file = 'README.md') {
  const errors = [];
  // Link targets and URLs are addresses, not example values.
  const scanned = text.replace(/\]\([^)]*\)/g, ']()').replace(/https?:\/\/\S+/g, '');
  for (const match of scanned.matchAll(new RegExp(SECRET_SHAPE, 'gi'))) {
    errors.push(`${file}: credential-shaped example \`${match[0]}\``);
  }
  const eco = text.slice(text.indexOf('## Part of the Ashlr ecosystem'));
  if (!eco) {
    errors.push(`${file}: missing Ashlr ecosystem section`);
  } else {
    for (const url of ECOSYSTEM_LINKS) {
      if (!eco.includes(`](${url}`)) errors.push(`${file}: missing ecosystem link ${url}`);
    }
  }
  return errors;
}

export function checkVersion(text) {
  const version = readFileSync(resolve(root, 'Cargo.toml'), 'utf8').match(/\[workspace.package\]\s*version = "([^"]+)"/)[1];
  return text.includes(`GitHub v${version} assets`) &&
    text.includes('latest: 0.7.9') && text.includes('release-candidate: 0.7.4')
    ? [] : ['distribution status: missing release version or verified npm tags'];
}

export function checkDocs() {
  const errors = guides.flatMap(file => checkGuide(readFileSync(resolve(root, file), 'utf8'), file));
  const status = readFileSync(resolve(root, 'docs/distribution-status.md'), 'utf8');
  errors.push(...checkGuide(status, 'docs/distribution-status.md'), ...checkVersion(status));
  errors.push(...checkReadmeSurface(readFileSync(resolve(root, 'README.md'), 'utf8')));
  return errors;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const errors = checkDocs();
  for (const error of errors) console.error(error);
  if (errors.length) process.exitCode = 1;
  else console.log(`PASS: ${guides.length + 1} distribution docs, local links, anchors and release version`);
}
