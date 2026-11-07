#!/usr/bin/env python3
"""Select workspace packages conservatively from NUL-delimited changed paths."""
import json
import os
import sys
from pathlib import Path


def select(metadata, paths):
    root = metadata['workspace_root']
    members = set(metadata['workspace_members'])
    packages = [p for p in metadata['packages'] if p['id'] in members]
    owners = {os.path.relpath(os.path.dirname(p['manifest_path']), root): p['id'] for p in packages}
    by_id = {p['id']: p for p in packages}
    reverse = {p['id']: set() for p in packages}
    for package in packages:
        for dep in package['dependencies']:
            path = dep.get('path')
            if path:
                owner = owners.get(os.path.relpath(path, root))
                if owner:
                    reverse[owner].add(package['id'])
    affected = set()
    for path in paths:
        parts = path.split('/')
        if (not path or path.startswith('/') or '..' in parts or
                any(part in ('Cargo.toml', 'Cargo.lock', 'build.rs', 'tests', 'test',
                             'fixtures', 'helpers', 'test_helpers', '.cargo', '.config')
                    for part in parts)):
            return None
        if any('test' in part.lower() or 'fixture' in part.lower() or
               'helper' in part.lower() or 'config' in part.lower() for part in parts):
            return None
        candidates = [(len(d), ident) for d, ident in owners.items()
                      if d != '.' and path.startswith(d + '/')]
        if not candidates:
            return None
        # Only source files are known to be crate-local. Other files may influence
        # tests, configuration, packaging, or code generation.
        if not path.endswith('.rs') or '/src/' not in '/' + path:
            return None
        affected.add(max(candidates)[1])
    pending = list(affected)
    while pending:
        for dependent in reverse[pending.pop()] - affected:
            affected.add(dependent)
            pending.append(dependent)
    return sorted(by_id[ident]['name'] for ident in affected)


def main():
    # This is a literal filesystem path, including names beginning with '-'.
    metadata_path = Path(sys.argv[1]).resolve(strict=True)
    with metadata_path.open(encoding='utf-8') as f:
        metadata = json.load(f)
    paths = [os.fsdecode(p) for p in sys.stdin.buffer.read().split(b'\0') if p]
    result = select(metadata, paths)
    if result is None:
        print('--workspace')
    else:
        for name in result:
            print(name)


if __name__ == '__main__':
    main()
