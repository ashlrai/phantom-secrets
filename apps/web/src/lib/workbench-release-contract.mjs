/** A presentation record, never permission to install, publish or execute. */
/** @typedef {{v:1, product:'workbench', repository:'ashlrai/phantom', packageName:'@ashlr/phantom', version:string, sourceSha:string, publishedAt:string, observedAt:string, releaseUrl:string, registryUrl:string, installCommand:string, macDownloadUrl:string|null, factsDigest:string}} PublicWorkbenchRelease */
const keys = ['v', 'product', 'repository', 'packageName', 'version', 'sourceSha', 'publishedAt', 'observedAt', 'releaseUrl', 'registryUrl', 'installCommand', 'macDownloadUrl', 'factsDigest'].sort();

/** Invalid or missing records produce no version/publication claims. @param {unknown} input @returns {PublicWorkbenchRelease|null} */
export function parseWorkbenchRelease(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return null;
  const value = /** @type {Record<string,unknown>} */ (input);
  if (Object.keys(value).sort().join(',') !== keys.join(',') || value.v !== 1 || value.product !== 'workbench' ||
      value.repository !== 'ashlrai/phantom' || value.packageName !== '@ashlr/phantom' ||
      typeof value.version !== 'string' || !/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(value.version) ||
      typeof value.sourceSha !== 'string' || !/^[a-f0-9]{40}$/.test(value.sourceSha) ||
      typeof value.factsDigest !== 'string' || !/^[a-f0-9]{64}$/.test(value.factsDigest)) return null;
  for (const key of ['publishedAt', 'observedAt']) {
    if (typeof value[key] !== 'string' || !Number.isFinite(Date.parse(value[key])) || new Date(value[key]).toISOString() !== value[key]) return null;
  }
  if (Date.parse(String(value.publishedAt)) > Date.parse(String(value.observedAt))) return null;
  const release = `https://github.com/ashlrai/phantom/releases/tag/v${value.version}`;
  const macBase = `https://github.com/ashlrai/phantom/releases/download/v${value.version}/Phantom_${value.version}_aarch64`;
  // Match only the legacy DMG or current signed app archive; the generated
  // release facts establish publication separately from this presentation parser.
  const macDownloads = [`${macBase}.dmg`, `${macBase}.app.tar.gz`];
  if (value.releaseUrl !== release || value.registryUrl !== `https://www.npmjs.com/package/@ashlr/phantom/v/${value.version}` ||
      value.installCommand !== `npm install -g @ashlr/phantom@${value.version}` ||
      (value.macDownloadUrl !== null && !macDownloads.some(url => value.macDownloadUrl === url))) return null;
  return /** @type {PublicWorkbenchRelease} */ (input);
}
