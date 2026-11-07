/** Closed, read-only selection for the existing CI jobs. */
import { appendFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { githubJson, REPO, REPOSITORY_ID } from '../release/qualify-full-ci.mjs';

export const DIAGNOSTIC_SCOPE = 'windows-native-diagnostics';
export function validationScope(env) {
  const scope = env.VALIDATION_SCOPE || 'full';
  if (!['full', DIAGNOSTIC_SCOPE].includes(scope)) throw new Error('unknown-ci-validation-scope');
  if (scope === DIAGNOSTIC_SCOPE && !(env.GITHUB_EVENT_NAME === 'workflow_dispatch' &&
      env.GITHUB_REPOSITORY === REPO && env.GITHUB_REPOSITORY_ID === String(REPOSITORY_ID) &&
      env.GITHUB_REF === 'refs/heads/main' && /^[a-f0-9]{40}$/.test(env.GITHUB_SHA ?? '') &&
      env.GITHUB_WORKFLOW_REF === `${REPO}/.github/workflows/ci.yml@refs/heads/main`)) {
    throw new Error('untrusted-windows-diagnostic-invocation');
  }
  return scope;
}
export async function selectValidationScope(env, api = githubJson) {
  const scope = validationScope(env);
  if (scope === DIAGNOSTIC_SCOPE) {
    const repository = await api(''), branch = await api('branches/main');
    if (!(repository.id === REPOSITORY_ID && repository.full_name === REPO && repository.default_branch === 'main' &&
        branch.name === 'main' && branch.protected === true && /^[a-f0-9]{40}$/.test(branch.commit?.sha ?? ''))) {
      throw new Error('diagnostic-default-branch-not-protected');
    }
  }
  return scope;
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const scope = await selectValidationScope(process.env);
    if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `scope=${scope}\n`);
    console.log(`CI validation scope: ${scope}`);
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
