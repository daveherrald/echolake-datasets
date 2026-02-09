#!/usr/bin/env python3
"""
Add sourcetype field to Splunk dataset file references.

Extracts sourcetype from the description field pattern:
  "{source} - {sourcetype}" -> sourcetype
  "{sourcetype}" (no " - ") -> sourcetype

Updates dataset.yaml files in-place.
"""

import yaml
import sys
from pathlib import Path


def extract_sourcetype(description: str) -> str | None:
    """Extract sourcetype from description field."""
    if not description:
        return None
    if ' - ' in description:
        return description.split(' - ', 1)[1].strip()
    return description.strip() or None


def patch_dataset(dataset_path: Path) -> dict:
    """Add sourcetype to file references in a dataset.yaml."""
    manifest_path = dataset_path / 'dataset.yaml'
    if not manifest_path.exists():
        return {'status': 'skip', 'reason': 'no manifest'}

    with open(manifest_path, 'r') as f:
        manifest = yaml.safe_load(f)

    if not manifest:
        return {'status': 'skip', 'reason': 'empty manifest'}

    refs = manifest.get('files', {}).get('references', [])
    if not refs:
        return {'status': 'skip', 'reason': 'no references'}

    modified = 0
    for ref in refs:
        if ref.get('sourcetype'):
            continue  # Already has sourcetype
        desc = ref.get('description', '')
        sourcetype = extract_sourcetype(desc)
        if sourcetype:
            ref['sourcetype'] = sourcetype
            modified += 1

    if modified == 0:
        return {'status': 'skip', 'reason': 'no changes needed'}

    with open(manifest_path, 'w') as f:
        yaml.safe_dump(manifest, f, default_flow_style=False, sort_keys=False)

    return {'status': 'patched', 'modified': modified}


def main():
    splunk_dir = Path(__file__).parent.parent / 'splunk'
    if not splunk_dir.exists():
        print(f"Error: {splunk_dir} not found")
        sys.exit(1)

    datasets = sorted([d for d in splunk_dir.iterdir() if d.is_dir()])
    print(f"Found {len(datasets)} Splunk datasets")

    stats = {'patched': 0, 'skip': 0, 'errors': 0, 'refs_modified': 0}

    for dataset_path in datasets:
        try:
            result = patch_dataset(dataset_path)
            if result['status'] == 'patched':
                stats['patched'] += 1
                stats['refs_modified'] += result['modified']
            else:
                stats['skip'] += 1
        except Exception as e:
            print(f"  Error: {dataset_path.name}: {e}")
            stats['errors'] += 1

    print(f"\nResults:")
    print(f"  Patched: {stats['patched']} datasets ({stats['refs_modified']} references)")
    print(f"  Skipped: {stats['skip']}")
    print(f"  Errors:  {stats['errors']}")


if __name__ == '__main__':
    main()
