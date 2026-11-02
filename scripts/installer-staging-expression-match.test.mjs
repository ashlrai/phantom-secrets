import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');

// The repository copy adds `|| die` guards that the published copy replaces
// with errexit; the creation expressions themselves must stay identical.
function stagingExpressions(source) {
  const lines = source.split('\n');
  const grab = (re) => {
    const hits = lines.filter((line) => re.test(line));
    assert.equal(hits.length, 1, `expected exactly one line matching ${re}`);
    return hits[0].replace(/\s*(\\|\|\| die ".*")$/, '').trim();
  };
  return {
    mktemp: grab(/^stage_root="\$\(mktemp -d /),
    chmod: grab(/^chmod 700 "\$stage_root"/),
    download: grab(/^download_dir=/),
    candidate: grab(/^candidate_dir=/),
    mkdir: grab(/^mkdir -m 700 "\$download_dir"/),
  };
}

test('both installers create their staging directories with the same expressions', () => {
  const repository = stagingExpressions(read('scripts/install.sh'));
  const web = stagingExpressions(read('apps/web/public/install.sh'));
  assert.deepEqual(web, repository);
  assert.equal(repository.mktemp, 'stage_root="$(mktemp -d "$install_parent/.${install_name}.install.XXXXXX")"');
  assert.equal(repository.mkdir, 'mkdir -m 700 "$download_dir" "$candidate_dir"');
});

test('the staging comparison detects drift in either copy', () => {
  const repository = read('scripts/install.sh');
  const web = read('apps/web/public/install.sh');
  const base = stagingExpressions(repository);
  for (const [from, to] of [
    ['mktemp -d "$install_parent/.${install_name}.install.XXXXXX"', 'mktemp -d "/tmp/.${install_name}.install.XXXXXX"'],
    ['chmod 700 "$stage_root"', 'chmod 755 "$stage_root"'],
    ['mkdir -m 700 "$download_dir"', 'mkdir -m 755 "$download_dir"'],
  ]) {
    for (const source of [repository, web]) {
      const mutated = source.replace(from, to);
      assert.notEqual(mutated, source);
      // Losing the expected line entirely also counts as detected drift.
      let drifted = false;
      try {
        drifted = JSON.stringify(stagingExpressions(mutated)) !== JSON.stringify(base);
      } catch {
        drifted = true;
      }
      assert.ok(drifted, `drift not detected: ${to}`);
    }
  }
});
