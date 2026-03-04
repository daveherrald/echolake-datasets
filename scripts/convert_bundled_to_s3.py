#!/usr/bin/env python3
"""Convert dataset.yaml bundled entries to S3 references.

Converts all dataset.yaml files in echolake-datasets from:
  files.bundled[].path → files.references[].uri (s3://echolake-datasets/...)

Usage:
  python3 scripts/convert_bundled_to_s3.py              # dry-run
  python3 scripts/convert_bundled_to_s3.py --apply       # write changes
"""

import argparse
import sys
from pathlib import Path

import yaml

BUCKET = "echolake-datasets"
DATASETS_DIR = Path(__file__).resolve().parent.parent / "datasets"


def convert_dataset(dataset_dir: Path, dry_run: bool = True) -> bool:
    """Convert a single dataset.yaml from bundled to S3 references.

    Returns True if changes were made (or would be made in dry-run).
    """
    yaml_path = dataset_dir / "dataset.yaml"
    if not yaml_path.exists():
        return False

    with open(yaml_path) as f:
        data = yaml.safe_load(f)

    if not data or "files" not in data:
        return False

    bundled = data["files"].get("bundled", [])
    if not bundled:
        print(f"  {dataset_dir.name}: no bundled entries, skipping")
        return False

    dataset_name = dataset_dir.name

    # Convert bundled → references
    new_references = []
    for entry in bundled:
        path = entry.get("path", "")
        filename = Path(path).name
        ref = {
            "uri": f"s3://{BUCKET}/{dataset_name}/data/{filename}",
            "format": entry.get("format", "csv"),
            "sourcetype": entry.get("sourcetype"),
        }
        if entry.get("description"):
            ref["description"] = entry["description"]
        new_references.append(ref)

    data["files"]["bundled"] = []
    data["files"]["references"] = new_references

    print(f"  {dataset_name}: {len(new_references)} bundled → references")

    if not dry_run:
        with open(yaml_path, "w") as f:
            yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)
        print(f"    wrote {yaml_path}")

    return True


def main():
    parser = argparse.ArgumentParser(description="Convert bundled entries to S3 references")
    parser.add_argument("--apply", action="store_true", help="Write changes (default: dry-run)")
    args = parser.parse_args()

    dry_run = not args.apply
    if dry_run:
        print("DRY RUN (use --apply to write changes)\n")

    changed = 0
    for dataset_dir in sorted(DATASETS_DIR.iterdir()):
        if not dataset_dir.is_dir():
            continue
        if convert_dataset(dataset_dir, dry_run=dry_run):
            changed += 1

    print(f"\n{'Would convert' if dry_run else 'Converted'} {changed} dataset(s)")


if __name__ == "__main__":
    main()
