#!/usr/bin/env python3
"""Regenerate and validate Atomic Red Team dataset metadata and factual READMEs."""

from __future__ import annotations

import argparse
import gzip
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


CHANNELS: dict[str, dict[str, str]] = {
    "sysmon": {
        "description": "Microsoft-Windows-Sysmon/Operational events",
        "category": "Sysmon",
        "event_channel": "Microsoft-Windows-Sysmon/Operational",
    },
    "security": {
        "description": "Windows Security events",
        "category": "Security",
        "event_channel": "Security",
    },
    "powershell": {
        "description": "Microsoft-Windows-PowerShell/Operational events",
        "category": "PowerShell",
        "event_channel": "Microsoft-Windows-PowerShell/Operational",
    },
    "application": {
        "description": "Windows Application events",
        "category": "Application",
        "event_channel": "Application",
    },
    "wmi": {
        "description": "Microsoft-Windows-WMI-Activity/Operational events",
        "category": "WMI",
        "event_channel": "Microsoft-Windows-WMI-Activity/Operational",
    },
    "system": {
        "description": "Windows System events",
        "category": "System",
        "event_channel": "System",
    },
    "taskscheduler": {
        "description": "Microsoft-Windows-TaskScheduler/Operational events",
        "category": "Task Scheduler",
        "event_channel": "Microsoft-Windows-TaskScheduler/Operational",
    },
}

DATASET_NAME_RE = re.compile(r"^(T\d{4}(?:\.\d{3})?)-(\d+)(?:\.\d+)?$")
TIMESTAMP_SHAPE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
BEGIN_FACTS = "<!-- BEGIN GENERATED ART FACTS -->"
END_FACTS = "<!-- END GENERATED ART FACTS -->"
EMPTY_DATASET_ALLOWLIST = {"T1218.005-3.02"}
KNOWN_POPULATED_ANALYSIS_EXCEPTIONS = {"T1546-6", "T1559-5", "T1654-1"}


@dataclass(frozen=True)
class FileFacts:
    path: str
    channel: str
    event_count: int
    event_ids: tuple[int, ...]
    earliest_raw: str | None
    earliest: datetime | None
    latest_raw: str | None
    latest: datetime | None


@dataclass
class Results:
    manifests: int = 0
    files: int = 0
    events: int = 0
    changed_manifests: int = 0
    changed_readmes: int = 0
    known_analysis_contradictions: int = 0
    errors: int = 0


def parse_timestamp(value: str) -> datetime:
    if not TIMESTAMP_SHAPE_RE.fullmatch(value):
        raise ValueError(f"Windows event timestamp must use six-digit UTC form: {value!r}")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def channel_from_path(path: str) -> str:
    name = Path(path).name
    suffix = ".xml.gz"
    if not name.endswith(suffix):
        raise ValueError(f"ART payload must end in {suffix}: {path}")
    channel = name[: -len(suffix)]
    if channel not in CHANNELS:
        raise ValueError(f"Unknown ART channel {channel!r}: {path}")
    return channel


def inspect_xml(path: Path, relative_path: str) -> FileFacts:
    channel = channel_from_path(relative_path)
    count = 0
    timestamp_count = 0
    event_ids: set[int] = set()
    earliest: tuple[datetime, str] | None = None
    latest: tuple[datetime, str] | None = None

    expected_channel = CHANNELS[channel]["event_channel"]
    try:
        with gzip.open(path, "rb") as stream:
            for _, element in ET.iterparse(stream, events=("end",)):
                if local_name(element.tag) != "Event":
                    continue
                count += 1
                systems = [child for child in element if local_name(child.tag) == "System"]
                if len(systems) != 1:
                    raise ValueError(f"{path}: event {count} has {len(systems)} System elements")
                system = systems[0]
                times = [child for child in system if local_name(child.tag) == "TimeCreated"]
                channels = [child for child in system if local_name(child.tag) == "Channel"]
                ids = [child for child in system if local_name(child.tag) == "EventID"]
                if len(times) != 1 or len(channels) != 1 or len(ids) != 1:
                    raise ValueError(
                        f"{path}: event {count} must have one TimeCreated, Channel, and EventID"
                    )
                value = times[0].get("SystemTime")
                if not value:
                    raise ValueError(f"{path}: event {count} TimeCreated lacks SystemTime")
                parsed = parse_timestamp(value)
                timestamp_count += 1
                if earliest is None or parsed < earliest[0]:
                    earliest = (parsed, value)
                if latest is None or parsed > latest[0]:
                    latest = (parsed, value)
                actual_channel = (channels[0].text or "").strip()
                if actual_channel != expected_channel:
                    raise ValueError(
                        f"{path}: event {count} channel is {actual_channel!r}, "
                        f"expected {expected_channel!r}"
                    )
                event_id = (ids[0].text or "").strip()
                if not event_id.isdigit():
                    raise ValueError(f"{path}: event {count} has invalid EventID {event_id!r}")
                event_ids.add(int(event_id))
                element.clear()
    except (OSError, EOFError, ET.ParseError) as exc:
        raise ValueError(f"Cannot parse gzip XML payload {path}: {exc}") from exc

    if count != timestamp_count:
        raise ValueError(f"{path}: found {count} events but {timestamp_count} timestamps")

    return FileFacts(
        path=relative_path,
        channel=channel,
        event_count=count,
        event_ids=tuple(sorted(event_ids)),
        earliest_raw=format_timestamp(earliest[0]) if earliest else None,
        earliest=earliest[0] if earliest else None,
        latest_raw=format_timestamp(latest[0]) if latest else None,
        latest=latest[0] if latest else None,
    )


def expected_file_entry(facts: FileFacts, current: dict[str, Any]) -> dict[str, Any]:
    channel = CHANNELS[facts.channel]
    log_source: dict[str, Any] = {
        "vendor": "Microsoft",
        "product": "Windows",
        "category": channel["category"],
    }
    log_source["event_ids"] = list(facts.event_ids)

    entry: dict[str, Any] = {
        "path": facts.path,
        "description": channel["description"],
        "format": "xml",
        "sourcetype": "XmlWinEventLog",
        "schema": "raw",
        "event_count": facts.event_count,
        "log_source": log_source,
    }
    for key, value in current.items():
        if key not in entry:
            entry[key] = value
    return entry


def payload_range(facts: list[FileFacts]) -> tuple[str, str] | None:
    populated = [fact for fact in facts if fact.earliest is not None]
    if not populated:
        return None
    earliest = min(populated, key=lambda fact: fact.earliest).earliest_raw
    latest = max(populated, key=lambda fact: fact.latest).latest_raw
    assert earliest is not None and latest is not None
    return earliest, latest


def analysis_claims_empty(dataset_dir: Path, event_count: int) -> bool:
    analysis_path = dataset_dir / "ANALYSIS.md"
    if event_count == 0 or not analysis_path.is_file():
        return False
    text = analysis_path.read_text(encoding="utf-8").lower()
    normalized = re.sub(r"[`*_]", "", text)
    return bool(re.search(r"files\.bundled.{0,100}\bempty\b", normalized, flags=re.DOTALL))


def expected_manifest(
    dataset_name: str,
    data: dict[str, Any],
    facts: list[FileFacts],
) -> dict[str, Any]:
    files = data.setdefault("files", {})
    bundled = files.get("bundled", [])
    if len(bundled) != len(facts):
        raise ValueError("Manifest file list changed while deriving facts")
    files["bundled"] = [
        expected_file_entry(fact, current) for fact, current in zip(facts, bundled)
    ]

    metadata = data.setdefault("metadata", {})
    time_range = payload_range(facts)
    if time_range is None:
        if dataset_name not in EMPTY_DATASET_ALLOWLIST:
            raise ValueError(f"Unexpected dataset with no packaged events: {dataset_name}")
        recorded = metadata.get("timestamp_range")
        if not isinstance(recorded, dict) or not recorded.get("earliest") or not recorded.get("latest"):
            raise ValueError(f"Allowlisted empty dataset lacks an execution instant: {dataset_name}")
        recorded["field"] = "execution_window"
    else:
        metadata["timestamp_range"] = {
            "earliest": time_range[0],
            "latest": time_range[1],
            "field": "System/TimeCreated/@SystemTime",
        }

    defaults = data.setdefault("defaults", {})
    defaults["schema"] = "raw"

    provenance = data.setdefault("provenance", {})
    if not isinstance(provenance, dict):
        raise ValueError(f"Provenance must be a mapping: {dataset_name}")
    regenerated = provenance.setdefault("regenerated", {})
    if not isinstance(regenerated, dict):
        raise ValueError(f"Regenerated provenance must be a mapping: {dataset_name}")
    regenerated["total_events"] = sum(fact.event_count for fact in facts)
    if regenerated.get("reason") in {
        "original .xml.gz were UTF-8-corrupted in git; rebuilt from bronze",
        "original .jsonl.gz were UTF-8-corrupted in git; rebuilt from bronze",
    }:
        regenerated["reason"] = (
            "original JSONL gzip files were corrupted; rebuilt from bronze, "
            "then converted to native Windows Event XML"
        )
    return data


def yaml_text(data: dict[str, Any]) -> str:
    return yaml.safe_dump(
        data,
        sort_keys=False,
        allow_unicode=False,
        width=4096,
    )


def technique_url(technique_id: str) -> str:
    return "https://attack.mitre.org/techniques/" + technique_id.replace(".", "/") + "/"


def md_escape(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def render_readme(dataset_dir: Path, data: dict[str, Any], facts: list[FileFacts]) -> str:
    metadata = data["metadata"]
    attack = metadata.get("mitre_attack") or {}
    techniques = attack.get("techniques") or []
    technique = techniques[0] if techniques else {}
    technique_id = str(technique.get("id", "Unknown"))
    technique_name = str(technique.get("name", "Unknown"))
    tactics = technique.get("tactics") or attack.get("tactics") or []
    match = DATASET_NAME_RE.match(dataset_dir.name)
    test_number = match.group(2) if match else "Unknown"
    host = (((data.get("environment") or {}).get("host") or {}).get("hostname") or "Unknown")
    time_range = payload_range(facts)
    total = sum(fact.event_count for fact in facts)

    rows = []
    for fact in facts:
        channel = CHANNELS[fact.channel]["category"]
        event_ids = ", ".join(str(value) for value in fact.event_ids) or "None"
        rows.append(
            f"| `{fact.path}` | {md_escape(channel)} | {fact.event_count:,} | {event_ids} |"
        )

    if time_range:
        range_text = f"`{time_range[0]}` through `{time_range[1]}`"
    else:
        recorded = metadata.get("timestamp_range") or {}
        instant = recorded.get("earliest", "unknown")
        range_text = (
            "Not available because the package contains no events. "
            f"The manifest retains the recorded execution instant `{instant}` until this dataset is resolved."
        )
    tactic_text = ", ".join(str(value) for value in tactics) or "None"
    return "\n".join(
        [
            "<!-- Generated by scripts/generate_art_metadata.py. -->",
            "",
            f"# {dataset_dir.name}: {technique_name}",
            "",
            "## Dataset metadata",
            "",
            "| Field | Value |",
            "|---|---|",
            f"| Description | {md_escape(metadata.get('description', ''))} |",
            f"| MITRE ATT&CK | [{technique_id}]({technique_url(technique_id)}) |",
            f"| Tactics | {md_escape(tactic_text)} |",
            f"| ART command | `Invoke-AtomicTest {technique_id} -TestNumbers {test_number}` |",
            f"| Collection host | {md_escape(host)} |",
            f"| Dataset version | {md_escape(metadata.get('version', ''))} |",
            "",
            "## Packaged telemetry",
            "",
            f"Total events: **{total:,}**",
            "",
            f"Payload time range: {range_text}",
            "",
            "| File | Channel | Events | Event IDs |",
            "|---|---|---:|---|",
            *rows,
            "",
            "All payloads use gzip-compressed native Windows Event XML, the `raw` EchoLake schema, and the `XmlWinEventLog` sourcetype.",
            "",
            "See [ANALYSIS.md](./ANALYSIS.md) for authored detection context and `dataset.yaml` for environment and provenance metadata.",
            "",
        ]
    )


def collection_facts(manifest_count: int, file_count: int, event_count: int) -> str:
    return "\n".join(
        [
            BEGIN_FACTS,
            "## Current package facts",
            "",
            f"- Datasets: {manifest_count:,}",
            f"- Bundled Windows Event XML files: {file_count:,}",
            f"- Packaged events: {event_count:,}",
            "- EchoLake schema: `raw`",
            "- EchoLake sourcetype: `XmlWinEventLog`",
            "",
            "These values are generated from the manifests and packaged payloads by `scripts/generate_art_metadata.py`.",
            "",
            "## Metadata maintenance",
            "",
            "Check the manifests and READMEs for drift:",
            "",
            "```bash",
            "python3 scripts/generate_art_metadata.py --check",
            "```",
            "",
            "Regenerate them after changing a packaged payload:",
            "",
            "```bash",
            "python3 scripts/generate_art_metadata.py --write",
            "```",
            END_FACTS,
        ]
    )


def replace_collection_facts(text: str, facts: str) -> str:
    if BEGIN_FACTS in text or END_FACTS in text:
        if text.count(BEGIN_FACTS) != 1 or text.count(END_FACTS) != 1:
            raise ValueError("ART README has malformed generated-facts markers")
        start = text.index(BEGIN_FACTS)
        end = text.index(END_FACTS) + len(END_FACTS)
        updated = text[:start] + facts + text[end:]
        return normalize_family_readme(updated)
    lines = text.splitlines()
    insert_at = 0
    if lines and lines[0].startswith("# "):
        insert_at = 1
        while insert_at < len(lines) and not lines[insert_at].strip():
            insert_at += 1
        while insert_at < len(lines) and not lines[insert_at].startswith("## "):
            insert_at += 1
    updated = "\n".join(lines[:insert_at] + ["", facts, ""] + lines[insert_at:]).rstrip() + "\n"
    return normalize_family_readme(updated)


def normalize_family_readme(text: str) -> str:
    replacements = {
        "sysmon.jsonl       # Sysmon operational events": "sysmon.xml.gz      # Native Sysmon Windows Event XML",
        "security.jsonl     # Windows Security events": "security.xml.gz    # Native Windows Security Event XML",
        "powershell.jsonl   # PowerShell operational events": "powershell.xml.gz  # Native PowerShell Windows Event XML",
        "Event format: JSONL (one JSON object per Windows event)": (
            "Event format: gzip-compressed native Windows Event XML"
        ),
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    return text


def collect_dataset_paths(art_root: Path, requested: list[str]) -> list[Path]:
    if requested:
        paths = [art_root / name / "dataset.yaml" for name in requested]
    else:
        paths = sorted(art_root.glob("*/dataset.yaml"))
    missing = [str(path) for path in paths if not path.is_file()]
    if missing:
        raise ValueError("Missing manifests: " + ", ".join(missing))
    return paths


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--dataset", action="append", default=[], help="ART dataset directory name")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="Check for generated metadata drift")
    mode.add_argument("--write", action="store_true", help="Rewrite manifests and factual READMEs")
    args = parser.parse_args()

    repo_root = args.repo_root.resolve()
    art_root = repo_root / "datasets" / "art"
    results = Results()
    derived: list[tuple[Path, dict[str, Any], list[FileFacts], str, str]] = []
    known_analysis_contradictions: set[str] = set()

    try:
        manifests = collect_dataset_paths(art_root, args.dataset)
        for manifest_path in manifests:
            dataset_dir = manifest_path.parent
            original = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
            if not isinstance(original, dict):
                raise ValueError(f"Manifest root is not a mapping: {manifest_path}")
            current_files = (original.get("files") or {}).get("bundled") or []
            declared_paths = [entry["path"] for entry in current_files]
            if len(declared_paths) != len(set(declared_paths)):
                raise ValueError(f"Manifest has duplicate payload paths: {manifest_path}")
            data_dir = dataset_dir / "data"
            actual_paths = sorted(
                path.relative_to(dataset_dir).as_posix()
                for path in data_dir.rglob("*")
                if path.is_file()
            )
            if sorted(declared_paths) != actual_paths:
                missing = sorted(set(actual_paths) - set(declared_paths))
                orphaned = sorted(set(declared_paths) - set(actual_paths))
                raise ValueError(
                    f"Payload declarations differ for {dataset_dir.name}; "
                    f"undeclared={missing}, missing={orphaned}"
                )
            facts = [
                inspect_xml(dataset_dir / entry["path"], entry["path"])
                for entry in current_files
            ]
            updated = expected_manifest(dataset_dir.name, original, facts)
            total_events = sum(fact.event_count for fact in facts)
            if analysis_claims_empty(dataset_dir, total_events):
                if dataset_dir.name not in KNOWN_POPULATED_ANALYSIS_EXCEPTIONS:
                    raise ValueError(
                        f"{dataset_dir / 'ANALYSIS.md'} claims a populated package is empty"
                    )
                known_analysis_contradictions.add(dataset_dir.name)
                results.known_analysis_contradictions += 1
                print(
                    f"KNOWN ANALYSIS CONTRADICTION: {dataset_dir.name} claims its "
                    f"{total_events} event package is empty",
                    file=sys.stderr,
                )
            expected_yaml = yaml_text(updated)
            expected_readme = render_readme(dataset_dir, updated, facts)
            derived.append((manifest_path, updated, facts, expected_yaml, expected_readme))
            results.manifests += 1
            results.files += len(facts)
            results.events += total_events

        if not args.dataset:
            stale_exceptions = KNOWN_POPULATED_ANALYSIS_EXCEPTIONS - known_analysis_contradictions
            if stale_exceptions:
                raise ValueError(
                    "Remove resolved analysis exceptions from the generator: "
                    + ", ".join(sorted(stale_exceptions))
                )

        for manifest_path, _, _, expected_yaml, expected_readme in derived:
            readme_path = manifest_path.parent / "README.md"
            current_yaml = manifest_path.read_text(encoding="utf-8")
            current_readme = readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""
            if current_yaml != expected_yaml:
                results.changed_manifests += 1
                if args.write:
                    manifest_path.write_text(expected_yaml, encoding="utf-8")
            if current_readme != expected_readme:
                results.changed_readmes += 1
                if args.write:
                    readme_path.write_text(expected_readme, encoding="utf-8")

        if not args.dataset:
            family_readme = art_root / "README.md"
            current = family_readme.read_text(encoding="utf-8")
            expected = replace_collection_facts(
                current,
                collection_facts(results.manifests, results.files, results.events),
            )
            if current != expected:
                if args.write:
                    family_readme.write_text(expected, encoding="utf-8")
                else:
                    results.errors += 1
                    print(f"OUT OF DATE: {family_readme.relative_to(repo_root)}", file=sys.stderr)

        if not args.write:
            if results.changed_manifests:
                results.errors += results.changed_manifests
                print(f"OUT OF DATE: {results.changed_manifests} ART manifests", file=sys.stderr)
            if results.changed_readmes:
                results.errors += results.changed_readmes
                print(f"OUT OF DATE: {results.changed_readmes} ART READMEs", file=sys.stderr)

        action = "updated" if args.write else "checked"
        print(
            f"ART {action}: {results.manifests} manifests, {results.files} files, "
            f"{results.events} events; {results.changed_manifests} manifest changes, "
            f"{results.changed_readmes} README changes; "
            f"{results.known_analysis_contradictions} known analysis contradictions"
        )
        return 1 if results.errors else 0
    except (KeyError, OSError, TypeError, ValueError, yaml.YAMLError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
