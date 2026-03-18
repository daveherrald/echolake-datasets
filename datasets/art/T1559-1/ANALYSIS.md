# T1559-1: Inter-Process Communication — Cobalt Strike Artifact Kit Pipe

## Technique Context

T1559 covers Inter-Process Communication as an execution mechanism. Adversaries exploit IPC channels — named pipes, COM, DDE — to execute code or communicate between processes. This test (test 1) emulates the named pipe pattern associated with the Cobalt Strike Artifact Kit: a compiled beacon or shellcode runner that creates a named pipe to receive and execute a payload. Named pipe detection is one of the primary behavioral signals used to identify Cobalt Strike activity in post-exploitation.

## What This Dataset Contains

The dataset captures 6 seconds of activity (01:14:52–01:14:57 UTC) across 26 Sysmon events, 10 Security events, and 34 PowerShell events.

The ART test framework launches a PowerShell process (SYSTEM context) which runs `whoami.exe` as a preflight check, then executes the test payload via cmd.exe:

```
"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\build\namedpipes_executor.exe" --pipe 1
```

Sysmon captures the full process tree. Security 4688 records the `cmd.exe` invocation with the full command line and the parent `powershell.exe`. Security 4689 shows `cmd.exe` exiting with status `0x1` (non-zero), indicating the executor ran but the pipe operation did not complete successfully — consistent with Defender blocking the payload before it could write. The PowerShell 4103 module logging events record `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass`, the standard ART test framework boilerplate present in every test.

Sysmon EID 17 (PipeEvent) captures two `\PSHost.*` named pipes created by the two PowerShell instances involved in the test framework. No Cobalt Strike pipe names (e.g., `\MSSE-*`, `\postex_*`, `\status_*`) appear in the pipe telemetry because the ART pipe executor (`namedpipes_executor.exe --pipe 1`) represents the *client* side that would connect to an already-running beacon's pipe — the pipe itself was never successfully created by a live beacon in this test.

Sysmon EID 7 (ImageLoad) records DLL loads for `powershell.exe` tagged with `technique_id=T1055` (Process Injection) and `technique_id=T1059.001` (PowerShell) from the sysmon-modular rule set. Sysmon EID 10 (ProcessAccess) records the PowerShell process accessing the `whoami.exe` and `cmd.exe` processes with access rights tagged as `technique_id=T1055.001` (DLL Injection).

## What This Dataset Does Not Contain (and Why)

The Cobalt Strike named pipe itself (`\MSSE-*` or similar artifact kit pipe) is not present. The ART test exercises the client-side pipe connection attempt (`namedpipes_executor.exe --pipe 1`), but a live Cobalt Strike beacon that would create and service the pipe was never running. The `cmd.exe` exit code of `0x1` and the absence of a Sysmon EID 18 (PipeConnected) event confirms no successful pipe connection occurred.

Windows Defender (v4.18.26010.5, signatures 1.445.536.0) was active with real-time protection and behavior monitoring enabled throughout. Defender likely terminated or blocked `namedpipes_executor.exe` before it could complete. No Sysmon EID 1 for `namedpipes_executor.exe` appears because the Sysmon ProcessCreate filter uses include-mode rules targeting known suspicious patterns — the executable name did not match any rule. Security 4688 (which audits all process creations) also does not show `namedpipes_executor.exe` directly, only the `cmd.exe` wrapper, suggesting the binary was blocked before the OS completed process creation.

Security audit policy has object access auditing disabled, so no file access events for the executor binary are present. Pipe connect events (Sysmon EID 18) require a separate filter rule and are not captured here.

## Assessment

This dataset documents a blocked Cobalt Strike Artifact Kit pipe simulation. The process chain (powershell.exe → cmd.exe → namedpipes_executor.exe) and command line are preserved with full fidelity in Security 4688. The `cmd.exe` non-zero exit and absence of the target pipe or EID 18 connect events confirm the technique was blocked before completion. The dataset is useful for training on the test framework-level telemetry pattern that surrounds blocked execution attempts.

## Detection Opportunities Present in This Data

- **Security 4688**: Full command line `namedpipes_executor.exe --pipe 1` under SYSTEM context with `cmd.exe` parent spawned from `powershell.exe`; the ART path `C:\AtomicRedTeam\atomics\..\ExternalPayloads\build\` is a strong indicator.
- **Sysmon EID 1**: `whoami.exe` spawned by `powershell.exe` under SYSTEM; part of the ART preflight pattern common across many tests in this series.
- **Sysmon EID 10**: `powershell.exe` accessing child processes with DLL-injection-class access rights; the access mask combined with SYSTEM context is suspicious.
- **Sysmon EID 7**: Multiple DLLs loaded into `powershell.exe` tagged with T1055 process injection rules from the sysmon-modular config.
- **Security 4689**: `cmd.exe` exit status `0x1` immediately after spawning the executor; this rapid failure pattern is consistent with AV/EDR termination.
- **PowerShell 4103**: `Set-ExecutionPolicy Bypass` under SYSTEM is the ART test framework boilerplate and correlates with every test in this series.
