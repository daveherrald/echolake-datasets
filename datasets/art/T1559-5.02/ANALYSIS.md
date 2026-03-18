# T1559-5: Inter-Process Communication — Cobalt Strike post-exploitation pipe (before 4.2)

## Technique Context

Inter-Process Communication (T1559) covers adversary abuse of Windows IPC mechanisms. This test simulates the named pipe used by Cobalt Strike versions before 4.2 for post-exploitation module communication. In these older versions, post-exploitation jobs (screenshot, keylog, hashdump, etc.) communicated with the main Beacon via a named pipe following the pattern `\\.\pipe\mojo.<pid>.<random>` — borrowing the `mojo` prefix from Chromium's IPC library, likely as a camouflage technique to blend with legitimate Chrome/Electron application traffic. This pattern was widely documented by researchers beginning around 2019-2020 and became a high-confidence Cobalt Strike indicator.

The test uses `namedpipes_executor.exe --pipe 5` to simulate the pre-4.2 `mojo.*` pipe creation.

## What This Dataset Contains

The dataset spans approximately 2 seconds on 2026-03-17 from ACME-WS06 (acme.local domain) and contains 130 events across PowerShell, Security, and Sysmon channels (no Application channel events).

**The attack command**, captured in Security EID 4688 and Sysmon EID 1:
```
cmd.exe /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\build\namedpipes_executor.exe" --pipe 5
```

Sysmon EID 1 tags `cmd.exe` with `technique_id=T1059.003,technique_name=Windows Command Shell`.

**Process chain** (Security EID 4688): `whoami.exe` pre-check, `cmd.exe /c namedpipes_executor.exe --pipe 5`, a second `whoami.exe`, and a cleanup `cmd.exe /c` (empty). Four EID 4688 events.

**Sysmon events** (19 total):
- EID 7 (Image Load): 9 events — .NET CLR assemblies into the test framework PowerShell
- EID 1 (Process Create): 4 events — `whoami.exe` (twice), the attacking `cmd.exe`, and the cleanup `cmd.exe`
- EID 10 (Process Access): 4 events — PowerShell accessing child processes with `0x1fffff`, tagged `T1055.001/Dynamic-link Library Injection`; notably this test shows three EID 10 events involving `whoami.exe` (versus two for other T1559 tests), suggesting the process access monitoring fired twice for the first `whoami.exe`
- EID 11 (File Create): 1 event
- EID 17 (Pipe Create): 1 event — `\PSHost.*` pipe from the test framework PowerShell

**PowerShell channel** (107 events): 104 EID 4104 blocks and 3 EID 4103 records. The 4103 records show `Set-ExecutionPolicy Bypass` and `Write-Host "DONE"`. Host ID `7a29159f-802b-4326-8639-b5874834194d` identifies this PowerShell instance. The Runspace ID prefix `2a5f9486-0664-4630` is unique to this test execution.

**Security channel**: Four EID 4688 process creation events.

## What This Dataset Does Not Contain

This test has no defended variant comparison entry in `defended_event_counts` (the field is an empty dict `{}`). This indicates the corresponding test was not run or not successfully captured in the defended ART dataset. T1559-5 is therefore the only dataset in this batch without a direct defended/undefended comparison pair.

No actual Cobalt Strike components are present. The `mojo.<pid>.<random>` pipe is simulated. No Chrome or Chromium processes are involved, though on a workstation with Chrome installed, legitimate `mojo.*` pipes from the browser would appear and require disambiguation.

The pre-4.2 `mojo.*` pipe pattern created by `namedpipes_executor.exe` is not confirmed in the Sysmon EID 17 samples, consistent with the pattern across all T1559 tests.

## Assessment

T1559-5 documents the older Cobalt Strike pipe pattern — the `mojo.<pid>.<random>` naming convention — which has been largely supplanted by the `postex_*` pattern since Cobalt Strike 4.2 (released mid-2020). Despite being an older pattern, it remains relevant because:

1. Threat actors may use older, modified, or cracked versions of Cobalt Strike
2. Some commodity malware families that borrowed Cobalt Strike's architecture continue to use the `mojo.*` pattern
3. Detection rules built against this pattern still fire for real-world threats

The absence of a defended comparison dataset makes it impossible to assess what Defender would have done with the `mojo.*` pipe name. The other T1559 tests show Defender-defended Sysmon counts of 26-36 versus 16-19 undefended, suggesting Defender was generating additional activity in response to the Cobalt Strike pipe names. For T1559-5, only the undefended baseline is available.

This dataset is structurally identical to T1559-4. The 19 Sysmon events, 4 Security EID 4688 events, and 107 PowerShell events match exactly. The only distinguishing information in the telemetry is `--pipe 5` in the command line.

## Detection Opportunities Present in This Data

**Named pipe `mojo.<pid>.<random>` pattern**: A named pipe matching `\pipe\mojo\.\d+\.[a-z0-9]+` created by any process outside of Chrome, Electron applications, or other known Chromium-based browsers is a Cobalt Strike pre-4.2 indicator. Context matters: this pipe name is entirely legitimate when created by Chrome. The absence of a Chrome or Electron process in the creating process's lineage is the key discriminator.

**Non-Chrome context**: In this dataset, the pipe is created by `namedpipes_executor.exe` (a child of cmd.exe, which is a child of PowerShell running as SYSTEM). There is no Chrome process anywhere in the process tree. A Sysmon EID 17 event showing `mojo.*` pipe creation from a process not in the Chromium/Electron family is a high-confidence Cobalt Strike indicator.

**Security EID 4688 process chain**: The PowerShell → cmd.exe → `namedpipes_executor.exe --pipe 5` chain from a SYSTEM context is documented. Real Cobalt Strike `mojo.*` pipes would typically originate from an injected process or the Beacon binary itself, not from PowerShell, but the pipe name itself is the primary detection surface regardless of origin.

**Historical threat intelligence value**: The `mojo.*` Cobalt Strike pipe pattern is extensively documented in public threat intelligence from 2019-2022. This dataset provides reference telemetry for testing detection rules against that historical pattern, particularly for environments that need to validate their Sysmon EID 17 monitoring covers the full range of Cobalt Strike pipe variants including the pre-4.2 naming convention.

**No defended comparison**: The absence of a defended baseline for this test is itself informative — it means there is no reference point for what Defender's response to the `mojo.*` pipe would look like. For detector development and testing, the undefended dataset here is the only available ground truth for this specific pipe pattern on this platform.
