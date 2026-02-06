#!/usr/bin/env python3
"""
Populate echolake-datasets repo from the echolake source project.

Copies and transforms datasets from the local echolake project into the
publishable repository structure.
"""

import os
import re
import shutil
import sys
from pathlib import Path

import yaml

# Paths
ECHOLAKE_DIR = Path("/Users/dave/projects/echolake")
REPO_DIR = Path("/Users/dave/projects/echolake-datasets")
SPLUNK_SRC = ECHOLAKE_DIR / "splunk-datasets"
BOTS_SRC = ECHOLAKE_DIR / "bots-datasets"
META_SRC = ECHOLAKE_DIR / "meta-datasets"

GITHUB_REPO = "daveherrald/echolake-datasets"
RELEASE_TAG = "v1.0.0"
RELEASE_BASE_URL = f"https://github.com/{GITHUB_REPO}/releases/download/{RELEASE_TAG}"


def normalize_filename(name: str) -> str:
    """Normalize filenames: replace colons and %3A with hyphens."""
    name = name.replace("%3A", "-")
    name = name.replace(":", "-")
    return name


def copy_splunk_datasets():
    """Copy all 1866 splunk dataset directories."""
    print("Copying splunk datasets...")
    dest = REPO_DIR / "splunk"
    dest.mkdir(exist_ok=True)

    count = 0
    for entry in sorted(SPLUNK_SRC.iterdir()):
        # Skip non-directories and special files
        if not entry.is_dir():
            continue

        target = dest / entry.name
        if target.exists():
            shutil.rmtree(target)
        shutil.copytree(entry, target)
        count += 1

    print(f"  Copied {count} splunk datasets")


def transform_splunk_catalog():
    """Transform splunk catalog: rename 'logsets' key to 'datasets'."""
    print("Transforming splunk catalog...")
    src_catalog = SPLUNK_SRC / "catalog.yaml"

    with open(src_catalog) as f:
        catalog = yaml.safe_load(f)

    # Rename key
    if "logsets" in catalog:
        catalog["datasets"] = catalog.pop("logsets")

    # Update name/description
    catalog["name"] = "splunk-security-content-datasets"
    catalog["description"] = (
        "1,866 EchoLake datasets generated from Splunk Security Content detections"
    )

    dest = REPO_DIR / "splunk" / "catalog.yaml"
    with open(dest, "w") as f:
        yaml.dump(catalog, f, default_flow_style=False, allow_unicode=True, width=120)

    print(f"  Wrote splunk catalog with {len(catalog.get('datasets', []))} entries")


def copy_bots_datasets():
    """Copy BOTS dataset manifests and data files with normalized filenames."""
    print("Copying BOTS datasets...")
    dest = REPO_DIR / "bots"
    dest.mkdir(exist_ok=True)

    for bots_dir in sorted(BOTS_SRC.iterdir()):
        if not bots_dir.is_dir():
            continue

        target = dest / bots_dir.name
        target.mkdir(exist_ok=True)

        # Copy dataset.yaml (we'll transform it separately)
        src_yaml = bots_dir / "dataset.yaml"
        if src_yaml.exists():
            shutil.copy2(src_yaml, target / "dataset.yaml")

        # Copy README if exists
        src_readme = bots_dir / "README.md"
        if src_readme.exists():
            shutil.copy2(src_readme, target / "README.md")

        # Copy data files with normalized names
        src_data = bots_dir / "data"
        if src_data.exists() and src_data.is_dir():
            target_data = target / "data"
            target_data.mkdir(exist_ok=True)

            for data_file in sorted(src_data.iterdir()):
                if data_file.is_file():
                    new_name = normalize_filename(data_file.name)
                    shutil.copy2(data_file, target_data / new_name)
                    if new_name != data_file.name:
                        print(f"    Renamed: {data_file.name} -> {new_name}")

        print(f"  Copied {bots_dir.name}")


def transform_botsv1_manifest():
    """Transform BOTSv1 dataset.yaml: bundled -> references with release URLs."""
    print("Transforming BOTSv1 manifest...")
    manifest_path = REPO_DIR / "bots" / "botsv1" / "dataset.yaml"

    with open(manifest_path) as f:
        manifest = yaml.safe_load(f)

    # Convert bundled files to references pointing to GitHub Release assets
    bundled = manifest.get("files", {}).get("bundled", [])
    references = []

    for entry in bundled:
        old_path = entry["path"]
        # Normalize the filename
        filename = normalize_filename(Path(old_path).name)
        new_path = f"data/{filename}"

        ref = {
            "uri": f"{RELEASE_BASE_URL}/{filename}",
            "path": new_path,
            "description": entry.get("description", ""),
            "format": entry.get("format", "csv"),
        }
        if "sourcetype" in entry:
            ref["sourcetype"] = entry["sourcetype"]
        references.append(ref)

    manifest["files"]["bundled"] = []
    manifest["files"]["references"] = references

    with open(manifest_path, "w") as f:
        yaml.dump(manifest, f, default_flow_style=False, allow_unicode=True, width=120)

    print(f"  Converted {len(references)} bundled files to references")


def transform_botsv1_small_manifest():
    """Transform BOTSv1-small dataset.yaml: bundled -> references with release URLs."""
    print("Transforming BOTSv1-small manifest...")
    manifest_path = REPO_DIR / "bots" / "botsv1-small" / "dataset.yaml"

    with open(manifest_path) as f:
        manifest = yaml.safe_load(f)

    bundled = manifest.get("files", {}).get("bundled", [])
    references = []

    for entry in bundled:
        old_path = entry["path"]
        filename = normalize_filename(Path(old_path).name)
        new_path = f"data/{filename}"

        ref = {
            "uri": f"{RELEASE_BASE_URL}/{filename}",
            "path": new_path,
            "description": entry.get("description", ""),
            "format": entry.get("format", "csv"),
        }
        if "sourcetype" in entry:
            ref["sourcetype"] = entry["sourcetype"]
        references.append(ref)

    manifest["files"]["bundled"] = []
    manifest["files"]["references"] = references

    with open(manifest_path, "w") as f:
        yaml.dump(manifest, f, default_flow_style=False, allow_unicode=True, width=120)

    print(f"  Converted {len(references)} bundled files to references")


def normalize_botsv1_tiny_manifest():
    """Normalize botsv1-tiny manifest paths (stays as bundled, just fix filenames)."""
    print("Normalizing BOTSv1-tiny manifest...")
    manifest_path = REPO_DIR / "bots" / "botsv1-tiny" / "dataset.yaml"

    with open(manifest_path) as f:
        manifest = yaml.safe_load(f)

    bundled = manifest.get("files", {}).get("bundled", [])
    for entry in bundled:
        old_path = entry["path"]
        filename = normalize_filename(Path(old_path).name)
        entry["path"] = f"data/{filename}"
        if entry["path"] != old_path:
            print(f"    Normalized: {old_path} -> {entry['path']}")

    with open(manifest_path, "w") as f:
        yaml.dump(manifest, f, default_flow_style=False, allow_unicode=True, width=120)


def copy_meta_datasets():
    """Copy meta-datasets and transform local: dependencies to github: references."""
    print("Copying meta-datasets...")
    dest = REPO_DIR / "meta"
    dest.mkdir(exist_ok=True)

    for entry in sorted(META_SRC.iterdir()):
        if not entry.is_dir():
            continue

        target = dest / entry.name
        if target.exists():
            shutil.rmtree(target)
        shutil.copytree(entry, target)

        # Transform dataset.yaml dependencies
        manifest_path = target / "dataset.yaml"
        if manifest_path.exists():
            transform_meta_dependencies(manifest_path)

        print(f"  Copied {entry.name}")


def transform_meta_dependencies(manifest_path: Path):
    """Transform local: paths to github: references in meta-dataset dependencies."""
    with open(manifest_path) as f:
        manifest = yaml.safe_load(f)

    deps = manifest.get("dependencies", [])
    for dep in deps:
        dataset_ref = dep.get("dataset", "")

        # Transform local:/Users/dave/projects/echolake/splunk-datasets/NAME
        # to github:daveherrald/echolake-datasets/splunk/NAME
        if "splunk-datasets/" in dataset_ref:
            match = re.search(r"splunk-datasets/([^/]+)$", dataset_ref)
            if match:
                name = match.group(1)
                dep["dataset"] = f"github:{GITHUB_REPO}/splunk/{name}"

        # Transform local: bots-datasets references similarly
        elif "bots-datasets/" in dataset_ref:
            match = re.search(r"bots-datasets/([^/]+)$", dataset_ref)
            if match:
                name = match.group(1)
                dep["dataset"] = f"github:{GITHUB_REPO}/bots/{name}"

    with open(manifest_path, "w") as f:
        yaml.dump(manifest, f, default_flow_style=False, allow_unicode=True, width=120)


def generate_bots_catalog():
    """Generate bots/catalog.yaml."""
    print("Generating BOTS catalog...")
    dest = REPO_DIR / "bots"
    catalog = {
        "name": "bots-datasets",
        "description": "Boss of the SOC (BOTS) security competition datasets",
        "datasets": [],
    }

    for entry in sorted(dest.iterdir()):
        if not entry.is_dir():
            continue
        manifest_path = entry / "dataset.yaml"
        if not manifest_path.exists():
            continue

        with open(manifest_path) as f:
            manifest = yaml.safe_load(f)

        meta = manifest.get("metadata", {})
        catalog["datasets"].append(
            {
                "path": entry.name,
                "name": meta.get("name", entry.name),
                "version": meta.get("version", "1.0.0"),
                "description": meta.get("description", ""),
                "tags": meta.get("tags", []),
            }
        )

    with open(dest / "catalog.yaml", "w") as f:
        yaml.dump(catalog, f, default_flow_style=False, allow_unicode=True, width=120)

    print(f"  Wrote BOTS catalog with {len(catalog['datasets'])} entries")


def generate_meta_catalog():
    """Generate meta/catalog.yaml."""
    print("Generating meta catalog...")
    dest = REPO_DIR / "meta"
    catalog = {
        "name": "meta-datasets",
        "description": "Curated collections of related security datasets",
        "datasets": [],
    }

    for entry in sorted(dest.iterdir()):
        if not entry.is_dir():
            continue
        manifest_path = entry / "dataset.yaml"
        if not manifest_path.exists():
            continue

        with open(manifest_path) as f:
            manifest = yaml.safe_load(f)

        meta = manifest.get("metadata", {})
        deps = manifest.get("dependencies", [])
        catalog["datasets"].append(
            {
                "path": entry.name,
                "name": meta.get("name", entry.name),
                "version": meta.get("version", "1.0.0"),
                "description": meta.get("description", ""),
                "tags": meta.get("tags", []),
                "dependency_count": len(deps),
            }
        )

    with open(dest / "catalog.yaml", "w") as f:
        yaml.dump(catalog, f, default_flow_style=False, allow_unicode=True, width=120)

    print(f"  Wrote meta catalog with {len(catalog['datasets'])} entries")


def generate_top_level_catalog():
    """Generate top-level catalog.yaml."""
    print("Generating top-level catalog...")

    # Count datasets per collection
    splunk_count = sum(
        1
        for p in (REPO_DIR / "splunk").iterdir()
        if p.is_dir() and (p / "dataset.yaml").exists()
    )
    bots_count = sum(
        1
        for p in (REPO_DIR / "bots").iterdir()
        if p.is_dir() and (p / "dataset.yaml").exists()
    )
    meta_count = sum(
        1
        for p in (REPO_DIR / "meta").iterdir()
        if p.is_dir() and (p / "dataset.yaml").exists()
    )

    catalog = {
        "name": "echolake-datasets",
        "description": "Curated security datasets for EchoLake",
        "version": "1.0.0",
        "collections": [
            {
                "path": "splunk",
                "name": "Splunk Security Content",
                "description": "1,866 datasets from Splunk Security Content detections",
                "dataset_count": splunk_count,
            },
            {
                "path": "bots",
                "name": "Boss of the SOC (BOTS)",
                "description": "Security competition datasets with realistic attack scenarios",
                "dataset_count": bots_count,
            },
            {
                "path": "meta",
                "name": "Meta-Datasets",
                "description": "Curated collections of related security datasets",
                "dataset_count": meta_count,
            },
        ],
        "total_datasets": splunk_count + bots_count + meta_count,
    }

    with open(REPO_DIR / "catalog.yaml", "w") as f:
        yaml.dump(catalog, f, default_flow_style=False, allow_unicode=True, width=120)

    print(f"  Total: {catalog['total_datasets']} datasets across {len(catalog['collections'])} collections")


def main():
    print(f"Populating echolake-datasets from {ECHOLAKE_DIR}")
    print(f"Target: {REPO_DIR}")
    print()

    # Step 1: Splunk datasets
    copy_splunk_datasets()
    transform_splunk_catalog()
    print()

    # Step 2: BOTS datasets
    copy_bots_datasets()
    transform_botsv1_manifest()
    transform_botsv1_small_manifest()
    normalize_botsv1_tiny_manifest()
    print()

    # Step 3: Meta-datasets
    copy_meta_datasets()
    print()

    # Step 4: Generate catalogs
    generate_bots_catalog()
    generate_meta_catalog()
    generate_top_level_catalog()
    print()

    print("Done! Review the output and commit.")


if __name__ == "__main__":
    main()
