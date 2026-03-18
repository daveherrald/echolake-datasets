# T1574.001-4: DLL — DLL Side-Loading using the Notepad++ GUP.exe binary

## Technique Context

T1574.001 (Hijack Execution Flow: DLL Search Order Hijacking) includes DLL side-loading, where an adversary places a malicious DLL alongside a legitimate, signed executable that loads DLLs by relative path. The signed executable acts as a proxy, loading the attacker's DLL under its trusted identity.

`GUP.exe` is the Notepad++ updater binary. It loads several DLLs from its own directory using relative paths, making it susceptible to side-loading if an attacker can write a malicious DLL to the same directory as `GUP.exe`. This test places a pre-built malicious DLL (from the ART atomics repository) alongside `GUP.exe` and executes the binary.

## What This Dataset Contains

The dataset captures 71 events across Sysmon (26), Security (10), and PowerShell (35) logs collected over approximately 4 seconds on ACME-WS02.

**The execution attempt is captured:**

Sysmon Event 1 shows:
- `cmd.exe /c "C:\AtomicRedTeam\atomics\T1574.002\bin\GUP.exe"` — GUP.exe launched from the ART atomics directory

Sysmon Event 10 (Process Access) shows:
- `powershell.exe` accessing `whoami.exe` and `cmd.exe` — test framework process spawning behavior

Sysmon Event 7 (Image Loaded) records DLLs loaded by PowerShell and the .NET runtime during the test framework execution, but notably does not show any attacker DLL being loaded by `GUP.exe`. The Defender DLLs (`MpOAV.dll`, `MpClient.dll`) are present, consistent with real-time protection scanning.

Security Event 4688 records `whoami.exe` and `cmd.exe` process creation. The `cmd.exe` exit code is `0x1` (non-zero), indicating `GUP.exe` either failed to run or exited with an error — consistent with Defender blocking the execution.

Security Event 4703 (Token Right Adjusted) is present, indicating a privilege adjustment during the PowerShell test framework startup.

## What This Dataset Does Not Contain (and Why)

**GUP.exe did not successfully side-load a malicious DLL.** Windows Defender blocked the execution. The `cmd.exe` exit code `0x1` confirms failure. No Sysmon Event 7 entry for a malicious DLL loaded by `GUP.exe` appears, and no Sysmon Event 1 for `GUP.exe` itself appears — suggesting the process either failed to start or was terminated before it logged.

**No GUP.exe process create (Event 1) in Sysmon.** The Sysmon include-mode filter would capture `GUP.exe` only if its name or parent matched filter rules. GUP.exe may not have matched, or it was blocked before creation was recorded.

**No file drop of malicious DLL.** The test used a pre-existing ART atomic binary; no file creation event for a malicious side-loaded DLL appears in the data. The DLL placement into the ART atomics directory happened before the test ran.

**No network connections.** A successful side-load payload would likely beacon; no outbound connections were recorded.

**Limited Security events (10 total).** The attack was blocked early, resulting in fewer process lifecycle events than other tests in this group.

## Assessment

This dataset shows Defender blocking a DLL side-loading attempt via GUP.exe. The telemetry available is primarily the test framework invocation and the cmd.exe failure exit code. The dataset is useful for illustrating what a blocked side-load attempt looks like — process spawn, immediate failure, no DLL load telemetry — rather than what a successful attack looks like. Correlation of cmd.exe non-zero exit with prior suspicious PowerShell execution is the primary detection signal.

## Detection Opportunities Present in This Data

- **Sysmon Event 1**: `cmd.exe /c "C:\AtomicRedTeam\atomics\T1574.002\bin\GUP.exe"` — execution of a known-vulnerable updater binary from a non-standard path.
- **Security Event 4689**: `cmd.exe` exit code `0x1` following a `GUP.exe` invocation — non-zero exit from a process expected to succeed indicates possible AV intervention.
- **Sysmon Event 10**: `powershell.exe` accessing `cmd.exe` — parent-child relationship indicating scripted execution.
- **Security Event 4703**: Token right adjustment during test framework startup — privilege adjustment events in SYSTEM context can indicate capability setup.
- **Absence of Sysmon Event 7 for GUP.exe DLL loads**: In environments where GUP.exe normally runs, an unexpected absence of its usual DLL load sequence could indicate Defender termination.
- **PowerShell Event 4103**: `Set-ExecutionPolicy -Scope Process -Force` — execution policy override consistent with scripted attack framework.
