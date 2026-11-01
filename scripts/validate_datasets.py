#!/usr/bin/env python3
"""Validate every EchoLake dataset manifest and bundled file offline."""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from echolake.datasets.models import DatasetManifest
from echolake.datasets.validation import validate_manifest_files


IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
MAX_ERROR_DETAILS = 100


@dataclass(frozen=True, order=True)
class Finding:
    """One deterministic repository validation error."""

    manifest: str
    code: str
    location: str
    message: str


@dataclass
class Results:
    """Aggregate validation results printed once at the end of a run."""

    discovered: int = 0
    loaded: int = 0
    bundled_entries: int = 0
    remote_references: int = 0
    local_files_checked: int = 0
    counts_checked: int = 0
    warnings: Counter[str] = field(default_factory=Counter)
    errors: list[Finding] = field(default_factory=list)


def _value_path(parent: str, key: Any) -> str:
    """Return an unambiguous path for one authored mapping key."""

    if isinstance(key, str) and IDENTIFIER.fullmatch(key):
        return f"{parent}.{key}"
    return f"{parent}[{key!r}]"


def _short_repr(value: Any, limit: int = 160) -> str:
    rendered = repr(value)
    if len(rendered) <= limit:
        return rendered
    return rendered[: limit - 3] + "..."


def authored_value_differences(
    authored: Any,
    dumped: Any,
    location: str = "$",
) -> list[tuple[str, str]]:
    """Find authored keys or values lost or changed by a model dump.

    Model-generated defaults are allowed. Every value present in the YAML input
    must remain at the same alias-aware path with the same Python type and value.
    """

    if isinstance(authored, dict):
        if not isinstance(dumped, dict):
            return [
                (
                    location,
                    f"mapping became {type(dumped).__name__}",
                )
            ]
        differences: list[tuple[str, str]] = []
        for key, value in authored.items():
            child = _value_path(location, key)
            if key not in dumped:
                differences.append((child, "authored key is absent from model_dump"))
                continue
            differences.extend(authored_value_differences(value, dumped[key], child))
        return differences

    if isinstance(authored, list):
        if not isinstance(dumped, list):
            return [
                (
                    location,
                    f"list became {type(dumped).__name__}",
                )
            ]
        if len(authored) != len(dumped):
            return [
                (
                    location,
                    f"list length changed from {len(authored)} to {len(dumped)}",
                )
            ]
        differences: list[tuple[str, str]] = []
        for index, (source_value, dumped_value) in enumerate(zip(authored, dumped)):
            differences.extend(
                authored_value_differences(
                    source_value,
                    dumped_value,
                    f"{location}[{index}]",
                )
            )
        return differences

    if type(authored) is not type(dumped) or authored != dumped:
        return [
            (
                location,
                "authored value {} ({}) became {} ({})".format(
                    _short_repr(authored),
                    type(authored).__name__,
                    _short_repr(dumped),
                    type(dumped).__name__,
                ),
            )
        ]
    return []


def _manifest_name(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _load_authored_yaml(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("manifest YAML must contain a top-level mapping")
    return value


def validate_repository(root: Path, *, check_counts: bool) -> Results:
    """Validate all manifests below ``root/datasets`` without network access."""

    results = Results()
    dataset_root = root / "datasets"
    manifests = sorted(
        dataset_root.rglob("dataset.yaml"),
        key=lambda path: path.relative_to(root).as_posix(),
    )
    results.discovered = len(manifests)

    for manifest_path in manifests:
        name = _manifest_name(manifest_path, root)
        try:
            authored = _load_authored_yaml(manifest_path)
        except (OSError, UnicodeError, ValueError, yaml.YAMLError) as error:
            results.errors.append(Finding(name, "yaml_load_failed", "$", str(error)))
            continue

        try:
            manifest = DatasetManifest.from_file(manifest_path)
        except Exception as error:
            results.errors.append(
                Finding(name, "manifest_model_failed", "$", str(error))
            )
            continue

        results.loaded += 1
        results.bundled_entries += len(manifest.files.bundled)
        results.remote_references += len(manifest.files.references)

        dumped = manifest.model_dump(by_alias=True)
        for location, message in authored_value_differences(authored, dumped):
            results.errors.append(
                Finding(name, "round_trip_value_lost", location, message)
            )

        report = validate_manifest_files(
            manifest,
            manifest_path.parent,
            check_counts=check_counts,
            require_registered_sourcetypes=True,
        )
        results.local_files_checked += report.files_checked
        results.counts_checked += report.counts_checked
        results.warnings.update(issue.code for issue in report.warnings)
        for issue in report.errors:
            message = issue.message
            if issue.path is not None:
                message += f" Declared path: {issue.path!r}."
            results.errors.append(
                Finding(name, issue.code, issue.location, message)
            )

    return results


def _format_counter(values: Counter[str]) -> str:
    return "; ".join(
        f"{key}={value:,}" for key, value in sorted(values.items())
    )


def print_results(results: Results, *, check_counts: bool) -> None:
    """Print deterministic details for errors and a concise aggregate summary."""

    errors = sorted(results.errors)
    for finding in errors[:MAX_ERROR_DETAILS]:
        message = " ".join(finding.message.splitlines())
        print(
            f"ERROR {finding.manifest} {finding.location} "
            f"[{finding.code}] {message}",
            file=sys.stderr,
        )
    if len(errors) > MAX_ERROR_DETAILS:
        print(
            f"ERROR {len(errors) - MAX_ERROR_DETAILS:,} additional error(s) omitted",
            file=sys.stderr,
        )

    count_text = (
        f"{results.counts_checked:,} runtime replay counts checked"
        if check_counts
        else "runtime replay counts skipped"
    )
    print(
        "Validated {loaded:,}/{discovered:,} manifests, {files:,} local files, "
        "{bundled:,} bundled entries, {remote:,} remote references, {counts}.".format(
            loaded=results.loaded,
            discovered=results.discovered,
            files=results.local_files_checked,
            bundled=results.bundled_entries,
            remote=results.remote_references,
            counts=count_text,
        )
    )
    if results.warnings:
        print(f"Warnings: {_format_counter(results.warnings)}.")
    if errors:
        print(f"FAILED with {len(errors):,} error(s).")
    else:
        print("PASS: all authored values and offline checks succeeded.")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate every datasets/**/dataset.yaml manifest offline.",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="Repository root containing datasets/ (default: inferred from this script)",
    )
    parser.add_argument(
        "--skip-counts",
        action="store_true",
        help="Skip runtime replay counting while retaining structural and path checks",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    root = args.root.expanduser().resolve()
    dataset_root = root / "datasets"
    if not dataset_root.is_dir():
        print(
            f"ERROR repository root has no datasets directory: {root}",
            file=sys.stderr,
        )
        return 2

    results = validate_repository(root, check_counts=not args.skip_counts)
    if results.discovered == 0:
        print(f"ERROR no dataset.yaml files found below {dataset_root}", file=sys.stderr)
        return 2

    print_results(results, check_counts=not args.skip_counts)
    return 1 if results.errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
