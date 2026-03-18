# T1548.002-2: Bypass User Account Control — Bypass UAC using Event Viewer (PowerShell)

## Technique Context

This test exploits the Event Viewer COM object registration mechanism. When `eventvwr.exe`
(or the underlying `mmc.exe` with `eventvwr.msc`) launches, it checks the registry key
`HKCU\Software\Classes\mscfile\shell\open\command` before the machine-wide equivalent in
`HKLM`. By writing `cmd.exe` (or any payload) into that per-user key and then launching Event
Viewer, an attacker causes Event Viewer to auto-elevate and spawn the payload with high
integrity — without any UAC prompt. The ART test uses PowerShell to write the registry key,
launch `mmc.exe eventvwr.msc`, then clean up.

## What This Dataset Contains

**Sysmon (38 events):** EIDs 7 (ImageLoad, 25), 10 (ProcessAccess, 3), 1 (ProcessCreate, 3),
11 (FileCreate, 3), 17 (PipeCreate, 2), 13 (RegistryValueSet, 2).

Key process-create events (EID 1):
- `whoami.exe` — ART pre-check, parent `powershell.exe`
- A child `powershell.exe` with the full registry-manipulation + launch payload:
  `"powershell.exe" & {New-Item ""HKCU:\software\classes\mscfile\shell\open\command"" -Force`
  `Set-ItemProperty ""HKCU:\software\classes\mscfile\shell\open\command"" -Name ""(default)"" -Value ""C:\Windows\System32\cmd.exe"" -Force`
  (parent: ART test framework `powershell.exe`, `IntegrityLevel: System`)
- `mmc.exe` with command line `"C:\Windows\system32\mmc.exe" "C:\Windows\System32\eventvwr.msc"`
  (parent: the registry-manipulation `powershell.exe`)
- A second `whoami.exe` (ART post-check)

EID 11 captures `mmc.exe` creating `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Event Viewer` — the directory Event Viewer creates on first run, confirming `mmc.exe` executed to the point of initializing its profile.

EID 13 shows `svchost.exe` setting a registry value under
`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask\Index` — ambient scheduled task update activity unrelated to the technique.

**Security (5 events):** EID 4688 (4) and EID 4702 (1).

EID 4688 records:
- `whoami.exe` (pre-check)
- `powershell.exe` with the registry key creation command line
- `mmc.exe "C:\Windows\System32\eventvwr.msc"`
- `whoami.exe` (post-check)

EID 4702 captures a scheduled task update for `\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask` — normal system activity coinciding with the test window.

**PowerShell (101 events):** EIDs 4104 (97) and 4103 (4). The EID 4103 module logging entries
show `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass` (ART test framework boilerplate)
and `New-Item` / `Set-ItemProperty` invocations against `HKCU:\software\classes\mscfile\shell\open\command`.
The 97 EID 4104 script-block events capture the full WinPwn-style PowerShell payload text including
the registry manipulation steps.

## What This Dataset Does Not Contain

**No cmd.exe child of mmc.exe.** The bypass relies on Event Viewer spawning `cmd.exe` when it
reads the poisoned `mscfile` handler. `cmd.exe` does not appear as a child of `mmc.exe` in
either EID 4688 or Sysmon EID 1. The technique attempted but the spawned `cmd.exe` was not
observed — this may be because the test runs as `NT AUTHORITY\SYSTEM` (already fully elevated),
so the UAC elevation path does not apply; `mmc.exe` launched but the COM elevation step that
would produce a high-integrity child was not observable in these logs.

**No elevated token transition.** All EID 4688 events show `TokenElevationTypeDefault (1)` —
there is no `TokenElevationTypeFull (2)` event that would mark a successful privilege elevation.

**No registry key cleanup events.** The test writes and implicitly reads the key but no explicit
`reg delete` or PowerShell `Remove-Item` cleanup of the `mscfile` key is logged, unlike
test `-4` (Fodhelper PowerShell) which logs explicit cleanup.

## Assessment

This dataset provides a complete view of the Event Viewer UAC bypass attempt. The attack
artifacts — the PowerShell command line writing `HKCU:\software\classes\mscfile\shell\open\command`,
the resulting `mmc.exe` launch, and the surrounding `whoami.exe` pre/post-checks — are all
present across both Sysmon and Security channels. Because the test executes as `NT AUTHORITY\SYSTEM`,
the actual elevation effect is moot, but the behavioral artifacts of the bypass technique are
fully logged. This dataset is richer than the defended equivalent (38 Sysmon events here vs.
38 in the defended run, though security increases from 11 to 5 and PowerShell from 40 to 101),
with the PowerShell channel now capturing the full script-block content that AMSI would have
intercepted or suppressed in the defended run.

## Detection Opportunities Present in This Data

- **Security EID 4688 / Sysmon EID 1:** `powershell.exe` command line containing
  `HKCU:\software\classes\mscfile\shell\open\command` combined with `Set-ItemProperty` or
  `New-Item` is a high-confidence indicator of this specific bypass variant.
- **Security EID 4688 / Sysmon EID 1:** `mmc.exe` with argument `eventvwr.msc` spawned by
  `powershell.exe` (rather than by `explorer.exe` or a user shell) is anomalous.
- **Sysmon EID 13:** Registry value sets targeting `HKCU\Software\Classes\mscfile\shell\open\command`
  from any process other than the shell or an installer warrant investigation.
- **PowerShell EID 4104:** Script-block text referencing `mscfile\shell\open\command` or
  `eventvwr.msc` in the same execution context as registry manipulation cmdlets.
