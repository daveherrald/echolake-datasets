# T1546-6: Event Triggered Execution — Load Custom DLL on mstsc Execution

## Technique Context

This test targets a persistence mechanism where a custom DLL is placed so that it is loaded when the Remote Desktop client (`mstsc.exe`) executes. This is a DLL search order or AppInit-style hijack targeting a specific application. The attacker plants a DLL that will be loaded by `mstsc.exe` on startup, enabling code execution whenever a user launches Remote Desktop. This technique is noteworthy in enterprise environments where IT staff frequently use RDP tools. Detection focuses on unexpected DLL loads by `mstsc.exe`, new DLL files in paths that precede system directories in the search order, and registry modifications that redirect DLL loading.

## What This Dataset Contains

This dataset contains no bundled data files. The `files.bundled` list is empty and the provenance `source_counts` and `dest_counts` are both empty objects. No events were collected for this test.

The collection window ran for approximately 7 seconds (epoch 1773444866–1773444873) and nothing was captured from any of the monitored channels (Sysmon, Security, PowerShell).

## What This Dataset Does Not Contain

The absence of data most likely reflects one of the following scenarios:

1. **Windows Defender blocked the test before any telemetry-generating activity occurred.** With real-time protection and behavior monitoring enabled, Defender may have intercepted the DLL write or the mstsc.exe launch, preventing even process creation events from appearing. Defender blocks that occur before the process creates do not generate 0xC0000022 exit codes in Security 4688 — they simply prevent the activity entirely.

2. **The Cribl Edge collection window did not overlap with the test execution.** The test ran for 7 seconds; if the test framework completed before Cribl Edge flushed its buffer, events may have been missed in the transport pipeline. The provenance verification confirms zero events reached the destination table.

3. **The mstsc.exe DLL hijack required an interactive session or display driver context** not available in the QEMU guest agent execution environment (Session 0, no desktop). mstsc.exe may have failed silently or immediately without generating Windows Event Log entries.

## Assessment

This dataset has no detection engineering value in its current form — it contains no events. It is documented here to represent a test execution that produced no telemetry, which is itself informative: it indicates that either the technique was blocked before generating observable evidence, or the execution environment was unsuitable for the technique's prerequisites. If you need telemetry for DLL-based persistence on mstsc.exe, re-run the test with Defender disabled (or with the DLL pre-signed/allowlisted), using an interactive desktop session rather than a headless SYSTEM context, and confirm the DLL is actually loaded via Sysmon EID=7 in the collection output.

## Detection Opportunities Present in This Data

No detection opportunities can be demonstrated from this dataset. For the technique in general:

1. **Sysmon EID=7 — unsigned or unexpected DLL loaded by `mstsc.exe`**: Any DLL loaded by the Remote Desktop client from outside `System32` or `SysWOW64` is suspicious.
2. **Sysmon EID=11 — DLL file creation in `mstsc.exe` search path directories**: A new `.dll` file written to a directory that precedes system paths in `mstsc.exe`'s DLL search order.
3. **Registry changes to `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags`** or similar AppShim entries for mstsc.exe.
