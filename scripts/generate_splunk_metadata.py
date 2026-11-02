#!/usr/bin/env python3
"""Generate pinned Splunk metadata, documentation, and BOTS reference checksums."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml


REPO_ROOT = Path(__file__).resolve().parents[1]
SPLUNK_ROOT = REPO_ROOT / "datasets" / "splunk-detections"
BOTS_ROOT = REPO_ROOT / "datasets" / "bots"
DATA_ROOT = REPO_ROOT / "scripts" / "data"
CATALOG_PATH = DATA_ROOT / "splunk_catalog.json"
ATTACK_PATH = DATA_ROOT / "mitre_attack_enterprise_18_1.json"
UNMAPPED_PATH = DATA_ROOT / "splunk_unmapped_reviews.yaml"
BOTS_HASHES_PATH = DATA_ROOT / "bots_sha256.json"
LOCK_PATH = SPLUNK_ROOT / "upstream.lock.yaml"
APACHE_LICENSE_PATH = SPLUNK_ROOT / "LICENSE"
MITRE_LICENSE_PATH = SPLUNK_ROOT / "MITRE-ATTACK-LICENSE.txt"
ATTRIBUTION_PATH = SPLUNK_ROOT / "ATTRIBUTION.md"
CHECKSUM_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
LFS_POINTER_RE = re.compile(
    rb"\Aversion https://git-lfs.github.com/spec/v1\n"
    rb"oid sha256:([0-9a-f]{64})\n"
    rb"size [0-9]+\n?\Z"
)
SOURCE_LINK_RE = re.compile(r"\*Source: \[Splunk Security Content\]\(([^)]+)\)\*")


class NoAliasDumper(yaml.SafeDumper):
    """Write repeated lists without YAML anchors."""

    def ignore_aliases(self, data: Any) -> bool:
        return True


def load_yaml(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected a mapping in {path}")
    return value


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def yaml_text(value: dict[str, Any]) -> str:
    return yaml.dump(
        value,
        Dumper=NoAliasDumper,
        sort_keys=False,
        allow_unicode=False,
        width=4096,
    )


def git_head(path: Path) -> str:
    return subprocess.check_output(
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        text=True,
    ).strip()


def git_blob(path: Path, revision: str, relative_path: str) -> bytes:
    return subprocess.check_output(
        ["git", "-C", str(path), "show", f"{revision}:{relative_path}"],
    )


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def verify_legal_files(lock: dict[str, Any]) -> None:
    """Require the local license copies bound by the upstream lock."""

    expected_apache = str(lock["sources"]["security_content"]["local_license_sha256"])
    actual_apache = sha256_bytes(APACHE_LICENSE_PATH.read_bytes())
    if actual_apache != expected_apache:
        raise ValueError(
            "Local Apache-2.0 license SHA-256 differs from upstream.lock.yaml"
        )
    mitre = lock["sources"]["mitre_attack"]
    if MITRE_LICENSE_PATH.name != str(mitre["local_license_path"]):
        raise ValueError("MITRE ATT&CK local license path differs from upstream.lock.yaml")
    actual_mitre = sha256_bytes(MITRE_LICENSE_PATH.read_bytes())
    if actual_mitre != str(mitre["local_license_sha256"]):
        raise ValueError(
            "Local MITRE ATT&CK license SHA-256 differs from upstream.lock.yaml"
        )


def slugify(value: str) -> str:
    return re.sub(r"-+", "-", re.sub(r"[^a-z0-9]+", "-", value.lower())).strip("-")


def normalize_description(value: Any) -> str:
    """Remove source formatting whitespace without truncating description text."""

    return "\n".join(line.rstrip() for line in str(value).strip().splitlines())


def source_rule_path(dataset_dir: Path, manifest: dict[str, Any]) -> str:
    extension = ((manifest.get("metadata") or {}).get("extensions") or {}).get(
        "org.echolake.upstream"
    )
    if isinstance(extension, dict) and isinstance(extension.get("path"), str):
        return extension["path"]
    match = SOURCE_LINK_RE.search((dataset_dir / "README.md").read_text(encoding="utf-8"))
    if not match:
        raise ValueError(f"Cannot recover the source rule path for {dataset_dir.name}")
    return match.group(1)


def attack_data_path(uri: str) -> str:
    path = urlparse(uri).path
    match = re.search(
        r"/(?:media/)?[Ss]plunk/attack_data/(?:raw/)?(?:refs/heads/)?[^/]+/(.+)\Z",
        path,
    )
    if not match:
        raise ValueError(f"Unsupported Splunk attack_data URL: {uri}")
    return re.sub(r"/+", "/", match.group(1)).lstrip("/")


def attack_data_sha256(
    repository: Path,
    revision: str,
    relative_path: str,
    cache: dict[str, str],
) -> str:
    """Return the content digest recorded by a pinned attack_data Git object."""

    if relative_path in cache:
        return cache[relative_path]
    blob = git_blob(repository, revision, relative_path)
    pointer = LFS_POINTER_RE.fullmatch(blob)
    digest = pointer.group(1).decode("ascii") if pointer else sha256_bytes(blob)
    cache[relative_path] = digest
    return digest


def build_catalog(
    security_content: Path,
    attack_data: Path,
    lock: dict[str, Any],
) -> dict[str, Any]:
    security_revision = lock["sources"]["security_content"]["revision"]
    attack_data_revision = lock["sources"]["attack_data"]["revision"]
    if git_head(security_content) != security_revision:
        raise ValueError("Security Content checkout does not match the locked revision")
    if git_head(attack_data) != attack_data_revision:
        raise ValueError("attack_data checkout does not match the locked revision")
    checksums: dict[str, str] = {}
    entries: list[dict[str, Any]] = []

    for manifest_path in sorted(SPLUNK_ROOT.glob("*/dataset.yaml")):
        dataset_dir = manifest_path.parent
        current = load_yaml(manifest_path)
        rule_path = source_rule_path(dataset_dir, current)
        rule_bytes = git_blob(security_content, security_revision, rule_path)
        rule = yaml.safe_load(rule_bytes)
        if not isinstance(rule, dict):
            raise ValueError(f"Source rule is not a mapping: {rule_path}")
        source_refs = [
            item
            for test in rule.get("tests") or []
            for item in test.get("attack_data") or []
        ]
        current_refs = (current.get("files") or {}).get("references") or []
        if len(source_refs) != len(current_refs):
            raise ValueError(
                f"Reference count changed for {dataset_dir.name}: "
                f"source={len(source_refs)} manifest={len(current_refs)}"
            )
        references = []
        for source_ref, current_ref in zip(source_refs, current_refs):
            path = attack_data_path(str(source_ref["data"]))
            current_path = attack_data_path(str(current_ref.get("uri", "")))
            if current_path != path:
                raise ValueError(
                    f"Reference order or identity changed for {dataset_dir.name}: "
                    f"source={path} manifest={current_path}"
                )
            checksum = attack_data_sha256(
                attack_data,
                attack_data_revision,
                path,
                checksums,
            )
            manifest_fields = {
                key: value
                for key, value in current_ref.items()
                if key not in {"uri", "checksum"}
            }
            references.append(
                {
                    "path": path,
                    "sha256": checksum,
                    "source": source_ref.get("source"),
                    "sourcetype": source_ref.get("sourcetype"),
                    "manifest_fields": manifest_fields,
                }
            )
        source_tags = rule.get("tags") or {}
        entries.append(
            {
                "dataset": dataset_dir.name,
                "rule_path": rule_path,
                "rule_sha256": sha256_bytes(rule_bytes),
                "detection_id": str(rule.get("id", "")),
                "title": str(rule["name"]),
                "version": int(rule["version"]),
                "date": str(rule.get("date", "")),
                "author": str(rule.get("author", "")),
                "status": str(rule.get("status", "")),
                "type": str(rule.get("type", "")),
                "description": normalize_description(rule.get("description", "")),
                "data_sources": list(rule.get("data_source") or []),
                "analytic_stories": list(source_tags.get("analytic_story") or []),
                "mitre_ids": list(source_tags.get("mitre_attack_id") or []),
                "tags": list((current.get("metadata") or {}).get("tags") or []),
                "references": references,
            }
        )
    return {
        "schema_version": 1,
        "security_content_revision": security_revision,
        "attack_data_revision": attack_data_revision,
        "dataset_count": len(entries),
        "datasets": entries,
    }


def external_id(value: dict[str, Any]) -> str | None:
    for reference in value.get("external_references") or []:
        if reference.get("source_name") == "mitre-attack" and reference.get("external_id"):
            return str(reference["external_id"])
    return None


def build_attack_lookup(stix_path: Path, lock: dict[str, Any], used_ids: set[str]) -> dict[str, Any]:
    raw = stix_path.read_bytes()
    attack_lock = lock["sources"]["mitre_attack"]
    actual_sha256 = sha256_bytes(raw)
    if actual_sha256 != str(attack_lock["sha256"]):
        raise ValueError(
            "ATT&CK STIX SHA-256 differs from upstream.lock.yaml: "
            f"expected={attack_lock['sha256']} actual={actual_sha256}"
        )
    bundle = json.loads(raw)
    objects = bundle.get("objects") or []
    tactics_by_stix: dict[str, str] = {}
    for item in objects:
        if item.get("type") == "x-mitre-tactic" and not item.get("x_mitre_deprecated"):
            tactics_by_stix[str(item["id"])] = str(item["x_mitre_shortname"])

    tactic_order: list[str] = []
    matrices = [
        item
        for item in objects
        if item.get("type") == "x-mitre-matrix"
        and item.get("name") == "Enterprise ATT&CK"
        and not item.get("x_mitre_deprecated")
    ]
    if len(matrices) != 1:
        raise ValueError(f"Expected one active Enterprise ATT&CK matrix, found {len(matrices)}")
    for tactic_ref in matrices[0].get("tactic_refs") or []:
        tactic_order.append(tactics_by_stix[str(tactic_ref)])

    techniques: dict[str, dict[str, Any]] = {}
    for item in objects:
        if item.get("type") != "attack-pattern":
            continue
        if item.get("revoked") or item.get("x_mitre_deprecated"):
            continue
        technique_id = external_id(item)
        if not technique_id or technique_id not in used_ids:
            continue
        phases = [
            str(phase["phase_name"])
            for phase in item.get("kill_chain_phases") or []
            if phase.get("kill_chain_name") == "mitre-attack" and phase.get("phase_name")
        ]
        ordered = [name for name in tactic_order if name in set(phases)]
        candidate = {"name": str(item["name"]), "tactics": ordered}
        if technique_id in techniques and techniques[technique_id] != candidate:
            raise ValueError(f"Ambiguous active ATT&CK objects for {technique_id}")
        techniques[technique_id] = candidate
    missing = sorted(used_ids - set(techniques))
    if missing:
        raise ValueError(f"ATT&CK v18.1 lacks mapped IDs: {', '.join(missing)}")
    return {
        "schema_version": 1,
        "version": str(attack_lock["version"]),
        "revision": str(attack_lock["revision"]),
        "source_sha256": actual_sha256,
        "tactic_order": tactic_order,
        "techniques": techniques,
    }


def pinned_attack_uri(revision: str, path: str) -> str:
    return f"https://media.githubusercontent.com/media/splunk/attack_data/{revision}/{path}"


def technique_url(technique_id: str) -> str:
    return "https://attack.mitre.org/techniques/" + technique_id.replace(".", "/") + "/"


def md(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def load_generation_inputs(
    *, skip_bots: bool = False
) -> tuple[dict[str, Any], dict[str, Any], dict[str, dict[str, str]], dict[str, str]]:
    lock = load_yaml(LOCK_PATH)
    verify_legal_files(lock)
    catalog = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    attack = json.loads(ATTACK_PATH.read_text(encoding="utf-8"))
    unmapped_raw = load_yaml(UNMAPPED_PATH)
    default_reviewed = str(unmapped_raw["reviewed"])
    unmapped: dict[str, dict[str, str]] = {}
    for key, value in unmapped_raw["datasets"].items():
        if isinstance(value, dict):
            rationale = str(value["rationale"])
            reviewed = str(value.get("reviewed", default_reviewed))
        else:
            rationale = str(value)
            reviewed = default_reviewed
        unmapped[str(key)] = {"reviewed": reviewed, "rationale": rationale}
    bot_hashes: dict[str, str] = {}
    if not skip_bots:
        bots = json.loads(BOTS_HASHES_PATH.read_text(encoding="utf-8"))
        bot_hashes = {str(key): str(value) for key, value in bots["files"].items()}
    if catalog["security_content_revision"] != lock["sources"]["security_content"]["revision"]:
        raise ValueError("Splunk catalog revision differs from upstream.lock.yaml")
    if catalog["attack_data_revision"] != lock["sources"]["attack_data"]["revision"]:
        raise ValueError("Splunk catalog attack_data revision differs from upstream.lock.yaml")
    if catalog["dataset_count"] != len(catalog["datasets"]):
        raise ValueError("Splunk catalog dataset count is inconsistent")
    unnormalized = [
        entry["dataset"]
        for entry in catalog["datasets"]
        if entry["description"] != normalize_description(entry["description"])
    ]
    if unnormalized:
        raise ValueError(
            f"Splunk catalog contains {len(unnormalized)} descriptions with formatting whitespace"
        )
    if attack["revision"] != lock["sources"]["mitre_attack"]["revision"]:
        raise ValueError("ATT&CK lookup revision differs from upstream.lock.yaml")
    if attack["version"] != str(lock["sources"]["mitre_attack"]["version"]):
        raise ValueError("ATT&CK lookup version differs from upstream.lock.yaml")
    if attack["source_sha256"] != lock["sources"]["mitre_attack"]["sha256"]:
        raise ValueError("ATT&CK lookup source SHA-256 differs from upstream.lock.yaml")
    return lock, catalog, unmapped, bot_hashes


def expected_manifest(
    entry: dict[str, Any],
    lock: dict[str, Any],
    attack: dict[str, Any],
    unmapped: dict[str, dict[str, str]],
) -> dict[str, Any]:
    security = lock["sources"]["security_content"]
    attack_data = lock["sources"]["attack_data"]
    mitre = lock["sources"]["mitre_attack"]
    techniques = []
    for technique_id in entry["mitre_ids"]:
        item = attack["techniques"][technique_id]
        techniques.append(
            {
                "id": technique_id,
                "name": item["name"],
                "tactics": list(item["tactics"]),
            }
        )
    tactic_set = {tactic for item in techniques for tactic in item["tactics"]}
    tactics = [tactic for tactic in attack["tactic_order"] if tactic in tactic_set]
    attack_mapping: dict[str, Any]
    if techniques:
        attack_mapping = {"status": "mapped"}
    else:
        review = unmapped.get(entry["dataset"])
        if not review:
            raise ValueError(f"Missing review for unmapped detection {entry['dataset']}")
        attack_mapping = {
            "status": "upstream-unmapped",
            "reviewed": review["reviewed"],
            "rationale": review["rationale"],
        }

    references = []
    for reference in entry["references"]:
        item = {
            "uri": pinned_attack_uri(str(attack_data["revision"]), reference["path"]),
            **reference["manifest_fields"],
            "checksum": f"sha256:{reference['sha256']}",
        }
        references.append(item)

    return {
        "metadata": {
            "name": entry["dataset"],
            "version": f"{entry['version']}.0.0",
            "description": entry["description"],
            "author": entry["author"],
            "updated": entry["date"],
            "license": "Apache-2.0",
            "tags": list(entry["tags"]),
            "mitre_attack": {"techniques": techniques, "tactics": tactics},
            "source_url": (
                "https://github.com/splunk/security_content/blob/"
                f"{security['revision']}/{entry['rule_path']}"
            ),
            "extensions": {
                "org.echolake.upstream": {
                    "project": "splunk/security_content",
                    "revision": security["revision"],
                    "path": entry["rule_path"],
                    "rule_sha256": f"sha256:{entry['rule_sha256']}",
                    "detection_id": entry["detection_id"],
                    "source_version": entry["version"],
                    "source_date": entry["date"],
                    "attack_data_project": "splunk/attack_data",
                    "attack_data_revision": attack_data["revision"],
                    "mitre_attack_version": mitre["version"],
                    "mitre_attack_revision": mitre["revision"],
                    "modified_by": "EchoLake",
                    "modification": (
                        "Pinned upstream references, added integrity hashes, and normalized "
                        "metadata for EchoLake."
                    ),
                    "attack_mapping": attack_mapping,
                }
            },
        },
        "files": {"bundled": [], "references": references},
        "defaults": {
            "echo": {
                "delta_factor": 1.0,
                "base_time": "earliest",
                "target_time": "now-1h",
            },
            "schema": "raw",
        },
    }


def render_readme(entry: dict[str, Any], manifest: dict[str, Any], lock: dict[str, Any]) -> str:
    metadata = manifest["metadata"]
    attack = metadata["mitre_attack"]
    technique_rows = [
        f"| [{item['id']}]({technique_url(item['id'])}) | {md(item['name'])} | {md(', '.join(item['tactics']))} |"
        for item in attack["techniques"]
    ]
    if not technique_rows:
        review = metadata["extensions"]["org.echolake.upstream"]["attack_mapping"]
        technique_rows = [f"| None | Upstream mapping reviewed | {md(review['rationale'])} |"]
    story_rows = [f"- {story}" for story in entry["analytic_stories"]] or ["- None"]
    data_rows = [f"- {source}" for source in entry["data_sources"]] or ["- None"]
    sample_rows = []
    for source, reference in zip(entry["references"], manifest["files"]["references"]):
        sample_rows.append(
            "| {source} | `{sourcetype}` | [pinned data]({uri}) | `{checksum}` |".format(
                source=md(source.get("source") or reference.get("description") or "Sample data"),
                sourcetype=md(source.get("sourcetype") or reference.get("sourcetype") or "auto"),
                uri=reference["uri"],
                checksum=reference["checksum"],
            )
        )
    security_revision = lock["sources"]["security_content"]["revision"]
    attack_revision = lock["sources"]["attack_data"]["revision"]
    return "\n".join(
        [
            "<!-- Generated by scripts/generate_splunk_metadata.py. -->",
            "<!-- EchoLake modified the upstream metadata as described in ../ATTRIBUTION.md. -->",
            "",
            f"# {entry['title']}",
            "",
            f"**Type:** {entry['type']}",
            "",
            f"**Author:** {entry['author']}",
            "",
            f"**Upstream version:** {entry['version']}",
            "",
            "## Description",
            "",
            entry["description"],
            "",
            "## MITRE ATT&CK",
            "",
            "| ID | Technique | Tactics |",
            "|---|---|---|",
            *technique_rows,
            "",
            "## Analytic Stories",
            "",
            *story_rows,
            "",
            "## Data Sources",
            "",
            *data_rows,
            "",
            "## Sample Data",
            "",
            "| Source | Sourcetype | URL | SHA-256 |",
            "|---|---|---|---|",
            *sample_rows,
            "",
            "## Provenance",
            "",
            f"- **Detection rule:** [pinned Splunk Security Content]({metadata['source_url']})",
            f"- **Security Content revision:** `{security_revision}`",
            f"- **Attack data revision:** `{attack_revision}`",
            f"- **MITRE ATT&CK version:** `{lock['sources']['mitre_attack']['version']}`",
            "- **Modification:** EchoLake pinned source references, added integrity metadata, and generated this document.",
            "",
            "## License",
            "",
            "The source detection metadata is licensed under [Apache License 2.0](../LICENSE). See [ATTRIBUTION.md](../ATTRIBUTION.md) for upstream revisions and modification details.",
            "",
            "MITRE ATT&CK names and tactics are provided under the [MITRE ATT&CK license](../MITRE-ATTACK-LICENSE.txt).",
            "",
        ]
    )


def attribution_text(lock: dict[str, Any]) -> str:
    security = lock["sources"]["security_content"]
    attack_data = lock["sources"]["attack_data"]
    mitre = lock["sources"]["mitre_attack"]
    return "\n".join(
        [
            "# Attribution and modifications",
            "",
            "The detection metadata in this directory is derived from "
            "[Splunk Security Content](https://github.com/splunk/security_content) "
            f"at revision `{security['revision']}`. The sample data is referenced from "
            "[Splunk attack_data](https://github.com/splunk/attack_data) "
            f"at revision `{attack_data['revision']}`. Copyright 2022 Splunk Inc.",
            "",
            "Both upstream Splunk projects are licensed under the Apache License 2.0. "
            "A copy is included in [LICENSE](LICENSE). Neither pinned upstream tree contains "
            "a `NOTICE` file.",
            "",
            "EchoLake modified the upstream material by selecting the 1,866 rules represented "
            "by this collection, converting rule metadata to EchoLake manifests, pinning rule "
            "and sample-data links, adding SHA-256 integrity values, adding MITRE ATT&CK names "
            "and tactics, recording reviewed unmapped rules, and generating the documentation. "
            "Each generated manifest records the source rule path, source revision, source rule "
            "hash, and a modification notice.",
            "",
            f"MITRE ATT&CK names and tactics come from Enterprise ATT&CK v{mitre['version']} "
            f"at revision `{mitre['revision']}`. Copyright 2020-2025 The MITRE Corporation. "
            "Approved for public release. Case number 19-3504. MITRE ATT&CK and ATT&CK are "
            "registered trademarks of The MITRE Corporation.",
            "",
            "The required MITRE copyright designation and license are reproduced in "
            "[MITRE-ATTACK-LICENSE.txt](MITRE-ATTACK-LICENSE.txt). The upstream license is "
            f"`{mitre['license_path']}` at Git blob `{mitre['license_blob_sha1']}`. See the "
            "[MITRE ATT&CK Terms of Use](https://attack.mitre.org/resources/terms-of-use/).",
            "",
            "The immutable inputs are listed in [upstream.lock.yaml](upstream.lock.yaml).",
            "",
        ]
    )


def family_readme(lock: dict[str, Any], catalog: dict[str, Any]) -> str:
    entries = catalog["datasets"]
    references = [ref for entry in entries for ref in entry["references"]]
    mapped = sum(bool(entry["mitre_ids"]) for entry in entries)
    unique_paths = len({ref["path"] for ref in references})
    return "\n".join(
        [
            "# Splunk Detection Datasets",
            "",
            f"{len(entries):,} datasets of sample attack data paired with detection logic from Splunk Security Content. Each manifest is generated from a pinned upstream rule and contains integrity-checked sample references.",
            "",
            "## Current package facts",
            "",
            f"- Datasets: {len(entries):,}",
            f"- Sample references: {len(references):,}",
            f"- Unique attack-data objects: {unique_paths:,}",
            f"- Datasets with ATT&CK mappings: {mapped:,}",
            f"- Reviewed upstream-unmapped datasets: {len(entries) - mapped:,}",
            "",
            "## Source lock",
            "",
            f"- `splunk/security_content`: `{lock['sources']['security_content']['revision']}`",
            f"- `splunk/attack_data`: `{lock['sources']['attack_data']['revision']}`",
            f"- MITRE ATT&CK Enterprise: v{lock['sources']['mitre_attack']['version']} at `{lock['sources']['mitre_attack']['revision']}`",
            "",
            "The immutable source definitions are recorded in [upstream.lock.yaml](upstream.lock.yaml). Each dataset README links to its pinned rule and sample objects.",
            "",
            "## Metadata maintenance",
            "",
            "Check generated manifests and documentation:",
            "",
            "```bash",
            "python3 scripts/generate_splunk_metadata.py --check",
            "```",
            "",
            "Regenerate after changing the committed source catalogs:",
            "",
            "```bash",
            "python3 scripts/generate_splunk_metadata.py --write",
            "```",
            "",
            "Refresh the source catalogs from local checkouts at the revisions in `upstream.lock.yaml`:",
            "",
            "```bash",
            "python3 scripts/generate_splunk_metadata.py --refresh-catalog \\",
            "  --security-content /path/to/security_content \\",
            "  --attack-data /path/to/attack_data \\",
            "  --attack-stix /path/to/enterprise-attack-18.1.json",
            "```",
            "",
            "## License and attribution",
            "",
            "Splunk Security Content and attack data are provided under [Apache License 2.0](LICENSE). See [ATTRIBUTION.md](ATTRIBUTION.md) for copyright, source revisions, and EchoLake modifications.",
            "",
            "MITRE ATT&CK names and tactics are provided under the [MITRE ATT&CK license](MITRE-ATTACK-LICENSE.txt).",
            "",
        ]
    )


def expected_bots_manifest(path: Path, bot_hashes: dict[str, str]) -> dict[str, Any]:
    data = load_yaml(path)
    defaults = data.setdefault("defaults", {})
    if "replay" in defaults:
        if "echo" in defaults:
            raise ValueError(f"Both defaults.echo and defaults.replay are present in {path}")
        defaults["echo"] = defaults.pop("replay")
    for reference in (data.get("files") or {}).get("references") or []:
        uri = str(reference["uri"])
        checksum = bot_hashes.get(uri)
        if not checksum or not re.fullmatch(r"[0-9a-f]{64}", checksum):
            raise ValueError(f"Missing BOTS SHA-256 for {uri}")
        reference["checksum"] = f"sha256:{checksum}"
    return data


def run(mode: str, *, skip_bots: bool = False) -> int:
    lock, catalog, unmapped, bot_hashes = load_generation_inputs(skip_bots=skip_bots)
    attack = json.loads(ATTACK_PATH.read_text(encoding="utf-8"))
    entries = {entry["dataset"]: entry for entry in catalog["datasets"]}
    actual_names = {path.parent.name for path in SPLUNK_ROOT.glob("*/dataset.yaml")}
    if actual_names != set(entries):
        missing = sorted(set(entries) - actual_names)
        extra = sorted(actual_names - set(entries))
        raise ValueError(f"Splunk catalog scope differs from manifests: missing={missing}, extra={extra}")
    if set(unmapped) != {name for name, entry in entries.items() if not entry["mitre_ids"]}:
        raise ValueError("The reviewed unmapped set differs from the catalog")

    changed: Counter[str] = Counter()
    for name in sorted(entries):
        manifest_path = SPLUNK_ROOT / name / "dataset.yaml"
        readme_path = manifest_path.parent / "README.md"
        manifest = expected_manifest(entries[name], lock, attack, unmapped)
        expected_yaml = yaml_text(manifest)
        expected_readme = render_readme(entries[name], manifest, lock)
        if manifest_path.read_text(encoding="utf-8") != expected_yaml:
            changed["splunk_manifests"] += 1
            if mode == "write":
                manifest_path.write_text(expected_yaml, encoding="utf-8")
        if not readme_path.exists() or readme_path.read_text(encoding="utf-8") != expected_readme:
            changed["splunk_readmes"] += 1
            if mode == "write":
                readme_path.write_text(expected_readme, encoding="utf-8")

    expected_family = family_readme(lock, catalog)
    family_path = SPLUNK_ROOT / "README.md"
    if family_path.read_text(encoding="utf-8") != expected_family:
        changed["family_readme"] += 1
        if mode == "write":
                family_path.write_text(expected_family, encoding="utf-8")

    expected_attribution = attribution_text(lock)
    if not ATTRIBUTION_PATH.exists() or ATTRIBUTION_PATH.read_text(encoding="utf-8") != expected_attribution:
        changed["attribution"] += 1
        if mode == "write":
            ATTRIBUTION_PATH.write_text(expected_attribution, encoding="utf-8")

    if not skip_bots:
        for manifest_path in sorted(BOTS_ROOT.glob("*/dataset.yaml")):
            expected = yaml_text(expected_bots_manifest(manifest_path, bot_hashes))
            if manifest_path.read_text(encoding="utf-8") != expected:
                changed["bots_manifests"] += 1
                if mode == "write":
                    manifest_path.write_text(expected, encoding="utf-8")

    detail = ", ".join(f"{key}={value}" for key, value in sorted(changed.items())) or "no changes"
    scope = "Splunk metadata" if skip_bots else "Splunk and BOTS metadata"
    print(f"{scope} {mode}: {detail}")
    if mode == "check" and changed:
        return 1
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--refresh-catalog", action="store_true")
    parser.add_argument("--security-content", type=Path)
    parser.add_argument("--attack-data", type=Path)
    parser.add_argument("--attack-stix", type=Path)
    parser.add_argument("--skip-bots", action="store_true", help="Operate on Splunk metadata only")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.refresh_catalog:
            required = [args.security_content, args.attack_data, args.attack_stix]
            if not all(required):
                raise ValueError(
                    "--refresh-catalog requires --security-content, --attack-data, and --attack-stix"
                )
            lock = load_yaml(LOCK_PATH)
            catalog = build_catalog(args.security_content, args.attack_data, lock)
            used_ids = {item for entry in catalog["datasets"] for item in entry["mitre_ids"]}
            attack = build_attack_lookup(args.attack_stix, lock, used_ids)
            write_json(CATALOG_PATH, catalog)
            write_json(ATTACK_PATH, attack)
            print(
                f"Refreshed {len(catalog['datasets'])} Splunk catalog entries and "
                f"{len(attack['techniques'])} ATT&CK techniques"
            )
            return 0
        return run("write" if args.write else "check", skip_bots=args.skip_bots)
    except (
        KeyError,
        OSError,
        subprocess.CalledProcessError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
        yaml.YAMLError,
    ) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
