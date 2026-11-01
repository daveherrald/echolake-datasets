#!/usr/bin/env python3
"""Replay a compact ART package that contains every Windows event channel."""

from __future__ import annotations

import gzip
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

from echolake.core.config import (
    Config,
    DatasetConfig,
    EchoConfig,
    OutputConfig,
    OutputDestinationConfig,
)
from echolake.core.echo import EchoEngine
from echolake.datasets.models import DatasetManifest


REPO_ROOT = Path(__file__).resolve().parents[1]
DATASET_DIR = REPO_ROOT / "datasets" / "art" / "T1548.002-2.02"
EXPECTED_CHANNELS = {
    "application.xml.gz",
    "powershell.xml.gz",
    "security.xml.gz",
    "sysmon.xml.gz",
    "system.xml.gz",
    "taskscheduler.xml.gz",
    "wmi.xml.gz",
}


def event_count(path: Path) -> int:
    count = 0
    with gzip.open(path, "rb") as stream:
        for _, element in ET.iterparse(stream, events=("end",)):
            if element.tag.rsplit("}", 1)[-1] == "Event":
                count += 1
                element.clear()
    return count


def decompressed(path: Path) -> bytes:
    with gzip.open(path, "rb") as stream:
        return stream.read()


def first_timestamp(path: Path) -> str | None:
    with gzip.open(path, "rb") as stream:
        for _, element in ET.iterparse(stream, events=("end",)):
            if element.tag.rsplit("}", 1)[-1] == "TimeCreated":
                return element.get("SystemTime")
    return None


def replay(output_dir: Path, *, no_shift: bool):
    config = Config(
        dataset=DatasetConfig(ref=f"local:{DATASET_DIR}"),
        echo=EchoConfig(no_shift=no_shift),
        output=OutputConfig(
            destination=OutputDestinationConfig(
                type="local",
                path=str(output_dir),
                path_template="{filename}",
            ),
            format="text",
            compression="gzip",
        ),
    )
    return EchoEngine(config).run()


def assert_output(
    output_dir: Path,
    expected_by_name: dict[str, int],
    *,
    unchanged: bool,
) -> None:
    for name, expected in expected_by_name.items():
        source = DATASET_DIR / "data" / name
        output = output_dir / name
        if not output.is_file():
            raise AssertionError(f"Missing replay output: {output}")
        actual = event_count(output)
        if actual != expected:
            raise AssertionError(f"{name}: output has {actual} events, expected {expected}")
        if unchanged and decompressed(output) != decompressed(source):
            raise AssertionError(f"{name}: passthrough changed the decompressed payload")


def main() -> None:
    manifest = DatasetManifest.from_file(DATASET_DIR / "dataset.yaml")
    entries = manifest.files.bundled
    expected_by_name = {Path(item.path).name: item.event_count or 0 for item in entries}
    channels = set(expected_by_name)
    if channels != EXPECTED_CHANNELS:
        raise SystemExit(
            f"Smoke fixture channels changed: expected {sorted(EXPECTED_CHANNELS)}, "
            f"got {sorted(channels)}"
        )
    expected_events = sum(expected_by_name.values())
    empty_files = sum(count == 0 for count in expected_by_name.values())
    if expected_events != 48 or empty_files != 2:
        raise SystemExit(
            f"Smoke fixture changed: expected 48 events and 2 empty files, "
            f"got {expected_events} events and {empty_files} empty files"
        )

    source_with_events = next(
        DATASET_DIR / "data" / name
        for name, count in expected_by_name.items()
        if count > 0
    )
    source_timestamp = first_timestamp(source_with_events)

    with tempfile.TemporaryDirectory(prefix="echolake-art-shift-") as temp_dir:
        output_dir = Path(temp_dir)
        stats = replay(output_dir, no_shift=False)
        failures = []
        if stats.errors != 0:
            failures.append(f"errors={stats.errors}, expected 0")
        if stats.event_count != expected_events:
            failures.append(f"event_count={stats.event_count}, expected {expected_events}")
        if stats.events_modified != expected_events:
            failures.append(
                f"events_modified={stats.events_modified}, expected {expected_events}"
            )
        if failures:
            raise SystemExit("Shifted ART replay failed: " + "; ".join(failures))
        assert_output(output_dir, expected_by_name, unchanged=False)
        shifted_timestamp = first_timestamp(output_dir / source_with_events.name)
        if shifted_timestamp == source_timestamp:
            raise SystemExit("Shifted ART replay left the first event timestamp unchanged")

    with tempfile.TemporaryDirectory(prefix="echolake-art-passthrough-") as temp_dir:
        output_dir = Path(temp_dir)
        stats = replay(output_dir, no_shift=True)
        failures = []
        if stats.errors != 0:
            failures.append(f"errors={stats.errors}, expected 0")
        if stats.event_count != expected_events:
            failures.append(f"event_count={stats.event_count}, expected {expected_events}")
        if stats.events_modified != 0:
            failures.append(f"events_modified={stats.events_modified}, expected 0")
        if failures:
            raise SystemExit("Passthrough ART replay failed: " + "; ".join(failures))
        assert_output(output_dir, expected_by_name, unchanged=True)

    print(
        f"ART replay smoke test passed: {expected_events} events across "
        f"{len(channels)} channels, including {empty_files} empty payloads"
    )


if __name__ == "__main__":
    main()
