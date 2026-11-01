# T1559-5: Capture Mismatch

## Package Status

This package is keyed as Atomic Red Team T1559 test 5, Cobalt Strike post-exploitation pipe before version 4.2. The recovered payload does not contain a test 5 invocation. It contains tests 1 through 4 in sequence, so this package must not be treated as test 5 ground truth.

The four bundled files contain 10,141 events from `2026-03-14T01:14:49.176000Z` through `2026-03-14T01:15:54.584000Z`. The manifest timestamp range is derived from those events and is ordered correctly.

| Channel | Events |
|---|---:|
| Security | 495 |
| Application | 92 |
| PowerShell | 9,203 |
| Sysmon | 351 |

## Payload Evidence

PowerShell EID 4104 records these ART invocations and cleanup commands:

| Test | Invocation | Cleanup |
|---:|---|---|
| 1 | `2026-03-14T01:14:56.070000Z` | `2026-03-14T01:15:05.614000Z` |
| 2 | `2026-03-14T01:15:12.025000Z` | `2026-03-14T01:15:21.603000Z` |
| 3 | `2026-03-14T01:15:27.881000Z` | `2026-03-14T01:15:37.543000Z` |
| 4 | `2026-03-14T01:15:44.153000Z` | `2026-03-14T01:15:53.618000Z` |

Security EID 4688 and Sysmon EID 1 record `cmd.exe` command lines that call `namedpipes_executor.exe --pipe 1`, `--pipe 2`, `--pipe 3`, and `--pipe 4`. There is no corresponding process-creation record for `--pipe 5`.

The PowerShell events include ART module and YAML parsing text that defines all available tests, including test 5. Definition text is not execution evidence. The Sysmon EID 17 records in this payload identify PowerShell host pipes and do not confirm creation of the expected technique pipe.

## Assessment

The payload supports analysis of the command attempts for T1559 tests 1 through 4. It does not establish execution of test 5, successful startup of `namedpipes_executor.exe`, or creation of a target named pipe. Detection work can use the observed `cmd.exe` command lines as attempt telemetry, with the package mismatch stated wherever results are reported.

T1559 test 5 requires a new capture with an explicit test 5 invocation and technique-specific pipe evidence before this package can serve as test 5 ground truth.
