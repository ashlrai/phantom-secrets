import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
import test from 'node:test';

const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const read = (path) => readFileSync(resolve(root, path), 'utf8');

const DOC = 'docs/device-code-ui.md';
const CLIENT = 'apps/web/src/app/device/device-authorization-client.tsx';

// Exact user-visible strings the guide must document. Each is pinned against
// the component source so the guide cannot drift from the rendered copy.
const VISIBLE_STRINGS = [
  'Authorize Device',
  'Enter the code shown in your terminal to authorize this device',
  'Device code',
  'XXXX-XXXX',
  'Enter 8 letters or numbers in the format XXXX-XXXX.',
  'Enter 8 letters or numbers. The code is displayed as XXXX-XXXX.',
  'This will sign you in via GitHub and link this device to your',
  'Signing in with GitHub...',
  'Approving...',
  'Device Authorized',
  'You can return to your terminal. The CLI will log you in',
  'Open your dashboard',
  'Failed to approve device',
  'Failed to connect. Please try again.',
  'Unable to read your sign-in session. Please try again.',
  'GitHub sign-in could not start. Please try again.',
  'GitHub sign-in did not complete. Please try again.',
  'Unable to complete sign-in. Please try again.',
  'Sign-in completed. Enter the current code from your terminal to authorize this device.',
  'Back to Phantom',
];

// Screen-reader-only status lines; checked quote-delimited so they cannot be
// satisfied by the "..."-suffixed button labels.
const SR_ONLY_STRINGS = [
  'Signing in with GitHub.',
  'Approving your device.',
];

// Accessibility wiring the guide documents for the visible states.
const A11Y_MARKERS = [
  'role="alert"',
  'role="status"',
  'aria-invalid',
  'aria-describedby',
  'aria-busy',
];

// Credential-handling mechanics that must stay out of a user-visible guide.
const FORBIDDEN = [
  /access[_ -]token/i,
  /\bbearer\b/i,
  /\btokens?\b/i,
  /session\s?storage|local\s?storage/i,
  /phantom_device_/i,
  /\boauth\b/i,
  /supabase/i,
  /`?Authorization`?\s*[:=]/,
  /NEXT_PUBLIC_/,
];

const flat = (text) => text.replace(/\s+/g, ' ');

test('device UI guide documents every user-visible string the component renders', () => {
  const guide = flat(read(DOC));
  const source = flat(read(CLIENT));
  for (const text of VISIBLE_STRINGS) {
    assert.ok(source.includes(text), `${CLIENT} no longer renders ${JSON.stringify(text)}; update the guide and this test`);
    assert.ok(guide.includes(text), `${DOC} does not document ${JSON.stringify(text)}`);
  }
  for (const text of SR_ONLY_STRINGS) {
    assert.ok(source.includes(text), `${CLIENT} no longer renders ${JSON.stringify(text)}; update the guide and this test`);
    assert.ok(guide.includes(`"${text}"`), `${DOC} does not quote the status line ${JSON.stringify(text)}`);
  }
});

test('device UI guide documents the input contract and accessibility wiring', () => {
  const guide = read(DOC);
  const source = read(CLIENT);
  for (const marker of A11Y_MARKERS) {
    assert.ok(source.includes(marker), `${CLIENT} no longer renders ${marker}`);
    assert.ok(guide.includes(marker), `${DOC} does not document ${marker}`);
  }
  // The displayed format and its local validation rule.
  assert.match(guide, /formatDeviceUserCode|two groups of four|four characters/);
  assert.match(guide, /exactly eight|exactly 8/);
  assert.match(guide, /placeholder `XXXX-XXXX`/);
});

test('device UI guide stays inside the user-visible boundary', () => {
  const guide = read(DOC);
  for (const pattern of FORBIDDEN) {
    assert.doesNotMatch(guide, pattern, `${DOC} documents credential handling matching ${pattern}`);
  }
  // The only "credential" mention allowed is the scope disclaimer itself.
  for (const match of guide.matchAll(/credential\w*/gi)) {
    assert.match(flat(guide.slice(match.index)), /^credential handling is intentionally out of scope/i);
  }
});

test('device UI guide is indexed and every relative link resolves', () => {
  const guide = read(DOC);
  assert.ok(
    read('docs/README.md').includes('[Device authorization page UI](device-code-ui.md)'),
    'docs/README.md does not index device-code-ui.md',
  );
  for (const [, target] of guide.matchAll(/\]\(([^)\s#]+)(?:#[^)]+)?\)/g)) {
    if (/^[a-z][a-z\d+.-]*:/i.test(target) || target.startsWith('/')) continue;
    assert.ok(
      existsSync(resolve(root, join(dirname(DOC), target))),
      `${DOC} links to missing ${target}`,
    );
  }
});
