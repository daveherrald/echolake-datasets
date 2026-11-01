# T1218.005-3.02: Empty Unresolved Package

## Package Status

This package is labeled `empty-unresolved`. It contains no replayable Mshta telemetry and must not be used as detection or technique ground truth.

The `data/` directory contains two valid gzip-compressed Windows Event XML wrappers:

| File | Events |
|---|---:|
| `powershell.xml.gz` | 0 |
| `sysmon.xml.gz` | 0 |

The retained `execution_window` instant is `2026-03-14T23:59:59Z`. It is provenance for the attempted collection, not an event timestamp.

## Provenance Discrepancy

`provenance.verification.source_counts` records 106 PowerShell events and 11 Sysmon events, for a historical total of 117. Regeneration recovered zero events. The historical source events are not present in this repository, so their contents cannot be reconstructed or described from the package.

The previous analysis reported 121 events and described specific process, file, image-load, and network evidence. Those claims were unsupported by the packaged files and did not agree with the manifest's historical total. They have been withdrawn.

## Assessment

This is an unresolved capture or rebuild gap. A zero-event package does not prove that the Atomic Red Team test produced no operating-system telemetry, that endpoint protection blocked it, or that the technique succeeded or failed.

Repair requires a fresh T1218.005 test 3 capture or recovery of the original 117 source events. Until then, the empty XML wrappers remain only to preserve package structure and make the missing telemetry explicit.
