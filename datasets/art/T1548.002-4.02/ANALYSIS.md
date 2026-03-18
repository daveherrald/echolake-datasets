# T1548.002-4: Bypass User Account Control — Bypass UAC using Fodhelper - PowerShell

## Technique Context

This test uses the same fodhelper.exe auto-elevation mechanism as test `-3`, but performs the
registry manipulation entirely through PowerShell cmdlets (`New-Item`, `New-ItemProperty`,
`Set-ItemProperty`) rather than via `cmd.exe` and `reg.exe`. The target key is
`HKCU:\software\classes\ms-settings\shell\open\command` with a `DelegateExecute` value set to
an empty string and the default value set to `cmd.exe`. After fodhelper spawns the elevated
shell, the test cleans up with a second PowerShell invocation that calls `Remove-Item` on
`HKCU:\software\classes\ms-settings`. This variant produces a richer telemetry footprint than
test `-3` because the registry manipulation is done in-process by PowerShell, generating both
Sysmon EID 12/13 events and detailed module logging.

## What This Dataset Contains

**Sysmon (44 events):** EIDs 7 (ImageLoad, 27), 1 (ProcessCreate, 5), 10 (ProcessAccess, 4),
17 (PipeCreate, 3), 11 (FileCreate, 2), 13 (RegistryValue, 2), 12 (RegistryObject, 1).

Key process-create events (EID 1):
- `whoami.exe` (ART pre-check)
- Child `powershell.exe` with the full bypass payload command line:
  `"powershell.exe" & {New-Item ""HKCU:\software\classes\ms-settings\shell\open\command"" -Force`
  `New-ItemProperty ""HKCU:\software\classes\ms-settings\shell\open\command"" -Name ""DelegateExecute"" -Value """" -Force`
  `Set-ItemProperty ""HKCU:\software\classes\ms-settings\shell\open\command"" -Name ""(default)"" -Value ""C:\Windows\System32\cmd.exe"" -Force`
  `Start-Process ""C:\Windows\System32\fodhelper.exe""}`
  (parent: ART test framework `powershell.exe`)
- `fodhelper.exe` — `"C:\Windows\System32\fodhelper.exe"`, parent: the bypass `powershell.exe`
- `whoami.exe` (ART post-check)
- Cleanup `powershell.exe`:
  `"powershell.exe" & {Remove-Item ""HKCU:\software\classes\ms-settings"" -force -Recurse -ErrorAction Ignore}`

EID 12 — `DeleteKey` for `HKU\.DEFAULT\Software\Classes\ms-settings\shell\open\command`
by the cleanup `powershell.exe` (PID 17060) — confirming the cleanup ran.

EID 11 — `MsMpEng.exe` (Defender, still installed but disabled) creating a temp file
`C:\Windows\Temp\01dcb631e653e9f3` — Defender's scan artifact, showing that even with
real-time protection off, the engine inspects processes on creation.

**Security (5 events):** Five EID 4688 events:
- `whoami.exe` (pre-check)
- Bypass `powershell.exe` with the full `New-Item`/`New-ItemProperty`/`Start-Process fodhelper`
  command line
- `fodhelper.exe` (parent: bypass `powershell.exe`) — present and captured
- `whoami.exe` (post-check)
- Cleanup `powershell.exe` with `Remove-Item "HKCU:\software\classes\ms-settings"`

**PowerShell (105 events):** EIDs 4104 (99), 4103 (6). Module logging (EID 4103) captures:
`Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass` (ART test framework),
`Remove-Item -Force -Recurse -ErrorAction Ignore -Path "HKCU:\software\classes\ms-settings"`
(cleanup, with parameter bindings showing the exact cleanup path). The 99 EID 4104
script-block events contain the full obfuscation-free payload.

## What This Dataset Does Not Contain

**No elevated cmd.exe child of fodhelper.** The expected attacker payoff — a high-integrity
`cmd.exe` child of `fodhelper.exe` — is not present in the Sysmon or Security samples. The
test runs as `NT AUTHORITY\SYSTEM`, so the UAC elevation path does not produce a distinguishable
elevated token event. The bypass mechanism ran (fodhelper was invoked and observed), but the
elevated shell it may have spawned is not captured in the sample window.

**No Sysmon EID 13 for the ms-settings key write.** The registry value sets to
`HKCU:\software\classes\ms-settings\shell\open\command` by the bypass PowerShell are not
present as Sysmon EID 13 events in the samples, even though EID 12 captures the subsequent
delete. The Sysmon config's registry monitoring may not cover HKCU class registration keys
for SetValue events in this configuration.

## Assessment

This is one of the more telemetry-rich UAC bypass datasets in the T1548.002 series. Security
EID 4688 records the complete lifecycle: registry setup PowerShell, `fodhelper.exe` invocation,
post-check, and cleanup PowerShell — all with full command lines. PowerShell module logging
captures the cleanup `Remove-Item` with parameter bindings, providing forensic evidence of
deliberate artifact cleanup (an attacker behavior pattern). The defended variant produced 38
Sysmon / 10 Security / 40 PowerShell events; this undefended run yields 44 / 5 / 105 —
notably fewer Security events (Defender was contributing some) but dramatically more PowerShell
content. The MsMpEng.exe temp file creation confirms Defender inspected the processes even in
its disabled state.

## Detection Opportunities Present in This Data

- **Security EID 4688 / Sysmon EID 1:** `powershell.exe` command line combining
  `ms-settings\shell\open\command`, `DelegateExecute`, and `Start-Process fodhelper.exe`
  in a single invocation.
- **Security EID 4688 / Sysmon EID 1:** `fodhelper.exe` with parent `powershell.exe`
  (rather than `explorer.exe` or `svchost.exe`) is anomalous.
- **Sysmon EID 12 (DeleteKey):** `HKU\.DEFAULT\Software\Classes\ms-settings\shell\open\command`
  deleted by `powershell.exe` immediately after `fodhelper.exe` runs — cleanup pattern.
- **PowerShell EID 4103:** `Remove-Item` targeting `HKCU:\software\classes\ms-settings` is
  a specific cleanup indicator.
- **Correlation:** The sequence of `New-Item`/`Set-ItemProperty` on `ms-settings\shell\open\command`
  → `fodhelper.exe` launch → `Remove-Item ms-settings` within a 10-second window.
