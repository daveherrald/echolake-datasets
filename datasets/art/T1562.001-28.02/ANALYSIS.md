# T1562.001-28: Disable or Modify Tools — Disable Defender Using NirSoft AdvancedRun

## Technique Context

MITRE ATT&CK T1562.001 (Impair Defenses: Disable or Modify Tools) includes using third-party
utilities to stop the Windows Defender service with elevated privilege. NirSoft AdvancedRun
is a legitimate administration utility that can launch processes under specific user contexts,
including as TrustedInstaller — a privilege level higher than SYSTEM that is used by the
Windows Modules Installer and is theoretically capable of bypassing Defender's Tamper
Protection. By running `sc.exe stop WinDefend` via AdvancedRun with `/RunAs 8`
(TrustedInstaller context), an adversary attempts to stop the WinDefend service using a
token that may circumvent protections that only guard against SYSTEM-level interference.
This technique has been observed in ransomware pre-staging phases.

In this dataset, Defender is **disabled** at the policy level prior to the test.

## What This Dataset Contains

The dataset captures 42 events across three channels (1 Application, 38 PowerShell,
3 Security) spanning approximately 4 seconds on ACME-WS06 (Windows 11 Enterprise
Evaluation, 2026-03-17T17:36:04Z–17:36:08Z).

**Security EID 4688 — Process creation capturing the full AdvancedRun invocation.** The
ART test framework spawns a child `powershell.exe` with:

```
"powershell.exe" & {Try {cmd /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\AdvancedRun.exe"
  /EXEFilename "$env:systemroot\System32\sc.exe"
  /WindowState 0
  /CommandLine "stop WinDefend"
  /StartDirectory ""
  /RunAs 8
  /Run} Catch{}
if(0){
  $CommandToRun = rmdir "$env:programdata\Microsoft\Windows Defender" -Recurse
  Try {cmd /c "...AdvancedRun.exe" /EXEFilename "...powershell.exe"
       /CommandLine "$CommandToRun" /RunAs 8 /Run} Catch{}
}}
```

The `/RunAs 8` parameter specifies TrustedInstaller context. The `Try/Catch` block
suppresses any errors from the AdvancedRun invocation. The `if(0)` block (permanently
false) gates a second action — deleting the Defender program data directory — that does
not execute in this test.

Two additional 4688 events capture `whoami.exe` pre- and post-execution identity checks.

**Application EID 15 — Windows Defender state update.** The Security Center registers
the Defender state as `SECURITY_PRODUCT_STATE_ON`, meaning the test triggered a Defender
health check or state refresh. This event fires in the same time window and reflects
Defender's security center registration being refreshed, not a successful shutdown.

**PowerShell EID 4100 — Two error events.** Both report:

```
Error Message = Exception calling "Start" with "0" argument(s): "Access is denied"
Fully Qualified Error ID = Win32Exception,Invoke-Process
```

The test framework `Invoke-Process` function could not launch the child PowerShell/AdvancedRun
process and raised `Win32Exception`. Access denied at the process creation level indicates
the host blocked the execution path despite Defender being disabled.

**PowerShell EID 4103 — One module pipeline event** logging the `Write-Host` error output
from the test framework.

**PowerShell EID 4104 — 35 script block events.** The boilerplate includes
`Set-ExecutionPolicy Bypass -Scope Process -Force` and `$ErrorActionPreference = 'Continue'`.
The cleanup block names `T1562.001 -TestNumbers 28`. No AdvancedRun-specific script block
content appears beyond what is captured in the 4688 command line.

## What This Dataset Does Not Contain

**No AdvancedRun.exe or sc.exe process creation events.** The 4688 command line shows the
attempt to run `AdvancedRun.exe` via `cmd /c`, but no 4688 event for `AdvancedRun.exe`
itself or for `sc.exe` appears. The Access Denied error at the test framework level blocked
execution before these child processes were spawned.

**No WinDefend service stop event.** Service control events (System EID 7036 or Security
EID 4659/7000-series) indicating the WinDefend service changed state are absent. The
service was not stopped.

**No Sysmon events.** The undefended dataset does not bundle Sysmon data. The defended
variant (art-T1562.001-28) includes Sysmon EID 8 (CreateRemoteThread from PowerShell to
`<unknown process>`) and task scheduler events for an unrelated OneSettings refresh task.
Neither of those appear here.

**No AdvancedRun.exe in the ExternalPayloads path executing.** The tool was staged at
`C:\AtomicRedTeam\atomics\..\ExternalPayloads\AdvancedRun.exe` but execution was blocked
before it ran. Whether the binary was written to disk is not confirmed by any event in
this dataset (no Sysmon EID 11 file creation is present).

## Assessment

This dataset captures a failed attempt to use NirSoft AdvancedRun to stop WinDefend via
TrustedInstaller context. Even with Defender disabled at the policy level, the attempt
failed with `Win32Exception: Access is denied` at the test framework level. The Application EID 15
`SECURITY_PRODUCT_STATE_ON` event is notable: it fires in response to the test activity
and reflects that Defender's Security Center registration remains active and healthy, which
is consistent with the service not having been stopped.

The defended variant shows the same `ACCESS_DENIED` outcome via Sysmon EID 8 and a
0xC0000022 exit code — the undefended run produces equivalent evidence for the actual attack
attempt (the 4688 command line with the AdvancedRun arguments) while omitting the Sysmon
process tree detail present in the defended dataset.

## Detection Opportunities Present in This Data

**Security EID 4688 — PowerShell command line contains `AdvancedRun.exe` with `/RunAs 8`.**
The `ExternalPayloads\AdvancedRun.exe` path, `/EXEFilename` pointing to `sc.exe`, and
`/CommandLine "stop WinDefend"` together form a highly specific indicator. Monitoring for
`AdvancedRun.exe` in 4688 command lines, especially with `/RunAs 8`, is a reliable
detection pivot.

**Security EID 4688 — `sc.exe stop WinDefend` in any parent context.** Even when routed
through AdvancedRun, a separate 4688 for `sc.exe stop WinDefend` would appear if the
AdvancedRun invocation succeeded. Its absence here confirms the technique was blocked, but
tuning for this command line combination remains valuable.

**Application EID 15 — `SECURITY_PRODUCT_STATE_ON` in tight temporal proximity to
`AdvancedRun.exe` execution.** The state refresh event fires in response to Defender
registration activity triggered by the attack attempt. This event alone is not sufficient
for detection, but co-occurrence with suspicious PowerShell or AdvancedRun activity in
a narrow time window is informative.

**PowerShell EID 4104 — `ExternalPayloads` path in script block.** The
`C:\AtomicRedTeam\atomics\..\ExternalPayloads\` path appearing in a 4688 command line or
4104 script block is a strong indicator of ART-based testing; in a real attack, the
equivalent path would be an adversary-controlled staging directory.
