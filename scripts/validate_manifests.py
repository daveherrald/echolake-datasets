#!/usr/bin/env python3
"""
Validate all dataset.yaml manifests in the repository.

Checks:
- YAML is valid and parseable
- Required fields are present (metadata.name, files)
- References have valid URIs
- Dependencies use github: references (not local:)
- Catalog entries match actual directories
"""

import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).parent.parent
REQUIRED_METADATA_FIELDS = {"name"}
ERRORS = []
WARNINGS = []


def error(path: str, msg: str):
    ERRORS.append(f"ERROR [{path}]: {msg}")


def warn(path: str, msg: str):
    WARNINGS.append(f"WARN  [{path}]: {msg}")


def validate_manifest(manifest_path: Path):
    """Validate a single dataset.yaml file."""
    rel_path = manifest_path.relative_to(REPO_ROOT)

    try:
        with open(manifest_path) as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        error(str(rel_path), f"Invalid YAML: {e}")
        return

    if not isinstance(data, dict):
        error(str(rel_path), "Root must be a mapping")
        return

    # Check metadata
    meta = data.get("metadata", {})
    if not meta:
        error(str(rel_path), "Missing 'metadata' section")
    else:
        for field in REQUIRED_METADATA_FIELDS:
            if field not in meta:
                error(str(rel_path), f"Missing metadata.{field}")

    # Check files section
    files = data.get("files")
    if files is None:
        warn(str(rel_path), "Missing 'files' section")
    elif isinstance(files, dict):
        # Validate references
        for ref in files.get("references", []):
            if isinstance(ref, dict) and "uri" in ref:
                uri = ref["uri"]
                if not uri.startswith(("http://", "https://", "s3://")):
                    warn(str(rel_path), f"Unusual URI scheme: {uri}")

        # Validate bundled files exist
        for bundled in files.get("bundled", []):
            if isinstance(bundled, dict) and "path" in bundled:
                bundled_path = manifest_path.parent / bundled["path"]
                if not bundled_path.exists():
                    error(str(rel_path), f"Bundled file not found: {bundled['path']}")

    # Check dependencies don't use local: paths
    for dep in data.get("dependencies", []):
        if isinstance(dep, dict):
            ds_ref = dep.get("dataset", "")
            if "local:" in ds_ref or ds_ref.startswith("/"):
                error(str(rel_path), f"Local dependency found: {ds_ref}")


def validate_catalog(catalog_path: Path):
    """Validate a catalog.yaml file."""
    rel_path = catalog_path.relative_to(REPO_ROOT)

    try:
        with open(catalog_path) as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        error(str(rel_path), f"Invalid YAML: {e}")
        return

    if not isinstance(data, dict):
        error(str(rel_path), "Root must be a mapping")
        return

    # Check datasets entries match actual directories
    datasets = data.get("datasets", [])
    catalog_dir = catalog_path.parent

    for entry in datasets:
        if isinstance(entry, dict) and "path" in entry:
            ds_dir = catalog_dir / entry["path"]
            if not ds_dir.is_dir():
                warn(str(rel_path), f"Catalog entry '{entry['path']}' has no directory")
            elif not (ds_dir / "dataset.yaml").exists():
                warn(str(rel_path), f"Catalog entry '{entry['path']}' has no dataset.yaml")


def main():
    print("Validating echolake-datasets manifests...")
    print()

    # Find all dataset.yaml files
    manifests = sorted(REPO_ROOT.rglob("dataset.yaml"))
    print(f"Found {len(manifests)} dataset.yaml files")

    for manifest in manifests:
        validate_manifest(manifest)

    # Find all catalog.yaml files (not top-level)
    catalogs = sorted(REPO_ROOT.glob("*/catalog.yaml"))
    print(f"Found {len(catalogs)} catalog.yaml files")

    for catalog in catalogs:
        validate_catalog(catalog)

    print()

    if WARNINGS:
        print(f"{len(WARNINGS)} warnings:")
        for w in WARNINGS[:20]:
            print(f"  {w}")
        if len(WARNINGS) > 20:
            print(f"  ... and {len(WARNINGS) - 20} more")
        print()

    if ERRORS:
        print(f"{len(ERRORS)} errors:")
        for e in ERRORS:
            print(f"  {e}")
        print()
        print("FAILED")
        sys.exit(1)
    else:
        print("ALL PASSED")
        sys.exit(0)


if __name__ == "__main__":
    main()
