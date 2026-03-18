# T1562.001-13: Disable or Modify Tools — AMSI Bypass (AMSI InitFailed)

## Technique Context

T1562.001 (Disable or Modify Tools) includes bypassing the Antimalware Scan Interface (AMSI), the Windows subsystem that allows security products to scan script content at runtime. AMSI intercepts PowerShell, JScript, VBScript, and other scripting hosts, passing content to registered security providers before execution. Bypassing AMSI allows malicious scripts to run without triggering security product scanning.

The InitFailed bypass works by locating the `amsiInitFailed` field in the `System.Management.Automation.AmsiUtils` class within the PowerShell process's loaded .NET assemblies, then setting that field to `$true`. When `amsiInitFailed` is true, the PowerShell AMSI integration treats initialization as having failed and skips all subsequent scans for the lifetime of that process. The bypass is entirely in-memory with no file system footprint.

The ART test executes:
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

This technique was first published around 2016 and is incorporated into numerous offensive toolkits. In-memory AMSI bypasses are operationally attractive because they do not require writing files, modifying registry keys, or stopping services — all of which generate more detectable artifacts.

## What This Dataset Contains

The dataset spans 3 seconds (2026-03-17 17:34:20–17:34:23 UTC) and contains 38 PowerShell events and 3 Security events. Notably, no Sysmon events are present — the Sysmon data channel was not collected for this test, or no Sysmon-matching activity occurred.

The bypass command is captured in Security EID 4688:
```
"powershell.exe" & {[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)}
```

This is the full bypass payload, visible in the process creation command line. Security EID 4688 records 3 process creation events: `whoami.exe` (pre-check), the bypass `powershell.exe`, and a second `whoami.exe` (post-check). All run as `NT AUTHORITY\SYSTEM`.

The PowerShell events break down to 35 EID 4104 (script block logging), 2 EID 4100 (error events), and 1 EID 4103 (module logging).

The 2 EID 4100 error events are critical artifacts: both record `Exception calling "Start" with "0" argument(s): "Access is denied"` with `Fully Qualified Error ID = Win32Exception,Invoke-Process`. This error indicates that after the bypass was set, the ART test framework attempted to invoke a process and was denied by the operating system — not by AMSI, but by a process execution restriction.

The EID 4103 event records `CommandInvocation(Write-Host): "Write-Host"` with `value="ERROR: Exception calling "Start" with "0" argument(s): "Access is denied"` — confirming the error was reported via the test framework's error output path.

The 35 EID 4104 events contain the ART preamble scriptblocks plus `$endEpoch = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()` — a timestamp capture from the test framework's execution tracking logic.

Critically, the bypass payload itself (`[Ref].Assembly.GetType(...)`) does not appear in any EID 4104 script block event. This is a direct consequence of the technique: the AMSI bypass causes the PowerShell process to skip AMSI scanning for subsequent script content, and AMSI scanning is what triggers script block logging for suspicious content. The bypass payload evades its own logging.

## What This Dataset Does Not Contain

No EID 4104 script block containing the bypass payload. The `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')` string does not appear in any PowerShell log event. This is by design: the bypass executes within a child PowerShell process spawned by the ART test framework. Once that PowerShell process runs the bypass line, AMSI is disabled for that process — but AMSI was already active when the process started and processed the initial script blocks, so the preamble is logged. The bypass line itself executes after AMSI is already bypassed in the running session, creating a race condition where the payload may not be scanned.

No Sysmon events. The Sysmon data channel contains no events for this test. The Sysmon ProcessCreate filter would have fired for the child PowerShell and `whoami.exe` under normal conditions. The absence suggests either the Sysmon driver was in a degraded state during this test window (this test runs shortly after T1562.001-11, the Sysmon driver unload test), or the collection configuration excluded Sysmon events for this specific capture window.

No in-memory patching artifact in the telemetry. The bypass operates by setting a .NET field value — there is no syscall trace, no registry write, no file creation. The only record is the command line captured before the payload executes.

Compared to the defended variant (15 Sysmon, 9 Security, 41 PowerShell), this undefended run has fewer events in each channel. The defended variant had Sysmon EID 8 (CreateRemoteThread) as the primary technique indicator — a behavioral signal from memory patching activity. That event is absent here, either because Sysmon was in a degraded state or because the execution path differed.

## Assessment

This dataset presents a challenging detection scenario. The bypass command is captured in Security EID 4688 — that is the primary artifact. However, the payload does not appear in PowerShell script block logging, which is the mechanism most defenders rely on for detecting obfuscated or malicious PowerShell.

The error events (EID 4100, 4103) are secondary artifacts that confirm the bypass ran and subsequent activity encountered restrictions. The `Access is denied` error from `Invoke-Process` suggests the post-bypass stage of the attack failed — the attacker bypassed AMSI but was blocked from spawning a process by a separate control.

The comparison with the defended variant is instructive: the defended run produced Sysmon EID 8 (CreateRemoteThread) as a behavioral indicator of the memory patching operation, which is absent here. This difference illustrates that the same technique can produce different observable behaviors depending on the monitoring stack state.

## Detection Opportunities Present in This Data

**Security EID 4688 command line**: `"powershell.exe" & {[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)}` is fully captured. The string `AmsiUtils` and `amsiInitFailed` in a process creation command line is a high-confidence indicator. This specific bypass pattern is well-known and string matching against process creation command lines is reliable for the InitFailed variant.

**Absence of script block logging for a known-malicious payload**: If your SIEM receives Security EID 4688 with the bypass command line but does not receive a corresponding PowerShell EID 4104 containing the payload, that discordance is itself detectable. The AMSI bypass succeeding prevents script block logging — so a Security 4688 with bypass content paired with minimal or absent PowerShell 4104 events is a meaningful correlation.

**PowerShell EID 4100 error events**: The `Win32Exception,Invoke-Process` / `Access is denied` error following the bypass attempt indicates post-bypass execution failure. These errors from a SYSTEM PowerShell process that also generated the bypass command line are contextually significant.

**SYSTEM-context PowerShell accessing .NET reflection APIs**: The `[Ref].Assembly.GetType()` pattern in PowerShell invocations by SYSTEM is uncommon in normal operations. .NET reflection to access internal security classes has essentially no legitimate use in standard enterprise environments.
