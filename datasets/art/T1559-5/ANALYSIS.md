# T1559-5: Inter-Process Communication — Before 4.2

## Technique Context

T1559 covers Inter-Process Communication as an execution channel. Test 5 emulates the named pipe pattern used by Cobalt Strike versions prior to 4.2 for post-exploitation modules. Pre-4.2, CS used more predictable pipe names — often static or partially static strings like `\mojo.*`, `\MSCryptHashProvider`, or short fixed identifiers — making them detectable by pipe name signature. Version 4.2 introduced randomization to evade these signatures, covered in test 4.

## What This Dataset Contains

This dataset contains no events. The `data/` directory is empty and `files.bundled` is an empty list in `dataset.yaml`. The provenance block records `source_counts: {}` and `dest_counts: {}`.

The timestamp range in `dataset.yaml` shows `earliest: 2026-03-14T01:15:56Z` and `latest: 2026-03-14T01:14:49Z` — a range where the latest timestamp is *before* the earliest, which is an artifact of the empty dataset state rather than a real time window.

## What This Dataset Does Not Contain (and Why)

No telemetry was collected for test 5. This outcome has two likely explanations consistent with the environment:

First, Windows Defender (v4.18.26010.5, real-time protection enabled, AMSI enabled) may have blocked the test framework entirely before any process creation events were generated. For tests 1–4, Defender blocked `namedpipes_executor.exe` but still allowed the `cmd.exe` wrapper to be created and logged. If Defender blocked the ART invocation at the PowerShell layer (e.g., via AMSI detecting the script or the process being denied before launch), no Security 4688 or Sysmon EID 1 events would be generated.

Second, the ART framework may have failed to locate or execute the pre-4.2 variant of the pipe executor. The pre-4.2 CS pipe patterns require a different build of `namedpipes_executor.exe` or a distinct pipe name configuration that may not have been present in the `ExternalPayloads/build/` directory at test time.

The absence of *any* telemetry distinguishes this from tests 1–4, where at least the `cmd.exe` wrapper and the ART test framework infrastructure were captured even though the pipe operation was blocked.

## Assessment

This is a null-result dataset. Its value lies in documenting a complete block at the test framework level: no process was created, no pipe was attempted, and no telemetry was generated. In a training context, this dataset establishes a baseline for what a fully suppressed execution looks like — useful for detection coverage analysis (confirming no false negatives against a zero-event ground truth) and for building data pipelines that handle empty datasets gracefully.

## Detection Opportunities Present in This Data

There are no events in this dataset and therefore no detection opportunities derived from the data itself. The null result is the signal: complete suppression by Defender or test framework failure before any OS-level instrumentation could capture execution.

For detection engineering purposes, the contrast between tests 1–4 (partial execution, cmd.exe wrapper captured) and test 5 (zero events) illustrates the difference between a technique being blocked mid-execution versus being blocked before execution begins.
