import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export const guides = ['README.md', 'docs/README.md', 'docs/getting-started.md',
  'docs/troubleshooting.md', 'docs/public-fact-sheet.md', 'docs/llms.txt',
  'docs/llms-full.txt', 'docs/delegation-quickstart.md', 'docs/ci-cd.md',
  'docs/platform-support.md', 'docs/index.html'];

export function checkGuide(text, file, base = root) {
  const errors = [];
  if (file !== 'docs/distribution-status.md' && !text.includes('distribution-status.md')) errors.push(`${file}: missing distribution status link`);
  if (/latest[`\s]*(?:currently resolves|remains)\s*`?0\.6\.0|still\s+(?:publishes|at)[\s\S]{0,80}?v?0\.7\.8|bump.*pending/i.test(text)) {
    errors.push(`${file}: stale current distribution claim`);
  }
  for (const match of text.matchAll(/(?:\[[^\]\n]+\]\(([^)\s]+)\)|href="([^"]+)")/g)) {
    const target = (match[1] ?? match[2]).split('#')[0];
    if (!target || /^[a-z][a-z\d+.-]*:/i.test(target) || target.startsWith('/')) continue;
    if (!existsSync(resolve(base, dirname(file), decodeURIComponent(target)))) {
      errors.push(`${file}: missing local link ${target}`);
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
  return errors;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const errors = checkDocs();
  for (const error of errors) console.error(error);
  if (errors.length) process.exitCode = 1;
  else console.log(`PASS: ${guides.length + 1} distribution docs, local links and release version`);
}
