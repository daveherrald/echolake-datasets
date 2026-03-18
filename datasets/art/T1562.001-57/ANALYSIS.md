# T1562.001-57: Disable or Modify Tools — Disable EventLog-Application ETW Provider Via Registry - PowerShell

## Technique Context

T1562.001 (Disable or Modify Tools) covers adversary actions to impair defenses by disabling or degrading security tooling. This test targets the Windows ETW (Event Tracing for Windows) subsystem by setting a registry value that disables a specific ETW provider used by the Application event log. Specifically, it sets `Enabled = 0` on the `EventLog-Application` autologger entry for provider GUID `{B6D775EF-1436-4FE6-BAD3-9E436319E218}` under `HKLM\System\CurrentControlSet\Control\WMI\Autologger`. This is a quiet, registry-only technique requiring no binary drop — the entire action is accomplished with a single PowerShell `New-ItemProperty` call.

## What This Dataset Contains

The dataset captures 84 events across Sysmon (36), Security (10), and PowerShell (38) channels over a five-second window.

**PowerShell script block logging (4104)** records the exact command issued:

```
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{B6D775EF-1436-4FE6-BAD3-9E436319E218}" -Name Enabled -Value 0 -PropertyType "DWord" -Force
```

**PowerShell module logging (4103)** records the corresponding `New-ItemProperty` cmdlet invocation with all parameter bindings (Path, Name, Value, PropertyType, Force), providing a second independent record of the action.

**Sysmon** events consist primarily of image loads (Event ID 7) marking three successive PowerShell process startups, a named pipe creation (Event ID 17 — `\PSHost.*`), a process access event (Event ID 10, rule `T1055.001`) from the ART test framework process touching the child PowerShell, and two process creates (Event ID 1) — `whoami.exe` (test framework identity check, rule `T1033`) and a subsequent PowerShell instance. File creates (Event ID 11) record PowerShell startup profile writes under `C:\Windows\System32\config\systemprofile`.

**Security** events (4688/4689) confirm process lifecycle for powershell.exe, conhost.exe, and whoami.exe running as `NT AUTHORITY\SYSTEM`. A single 4703 (token right adjusted) event is present.

The PowerShell log includes the expected test framework boilerplate: `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass` (recorded in 4103), plus batches of four identical 4104 fragments per PowerShell invocation containing internal PS error-handling closures (`{ Set-StrictMode -Version 1; $_.PSMessageDetails }` etc.).

## What This Dataset Does Not Contain (and Why)

There is no Sysmon Event ID 13 (registry value set). The sysmon-modular configuration used here does not include a rule matching `HKLM\System\CurrentControlSet\Control\WMI\Autologger` registry paths for `SetValue` events. The registry modification is confirmed only through PowerShell logging, not through Sysmon's registry monitoring.

There are no Security Event ID 4657 (registry value modification) events because object access auditing is not enabled in the audit policy configuration.

No process create events for `reg.exe` appear because this technique uses the PowerShell `New-ItemProperty` cmdlet rather than the command-line `reg` utility — the modification happens within the PowerShell process.

## Assessment

The technique executed successfully. The PowerShell script blocks confirm the registry write completed without error (`New-ItemProperty` returned normally and the 4103 module log shows no terminating error). Windows Defender did not block this action — it is a benign-looking registry write with no binary payload that triggers behavioral signatures.

The absence of Sysmon registry telemetry is a meaningful gap: an analyst relying on Sysmon alone for registry monitoring would not detect this change. Detection depends on PowerShell logging being active and forwarded, which it is here.

## Detection Opportunities Present in This Data

- **PowerShell 4104 (script block logging):** The exact registry path and GUID are captured verbatim. A rule matching `Autologger` + `Enabled` + `Value 0` in script block text will fire reliably on this technique.
- **PowerShell 4103 (module logging):** `CommandInvocation(New-ItemProperty)` with `Path` containing `WMI\Autologger` and `Name` = `Enabled` with `Value` = `0` is detectable.
- **Security 4688:** PowerShell launched as `NT AUTHORITY\SYSTEM` in a non-interactive session (`TerminalSessionId: 0`) is contextually suspicious, especially with `whoami.exe` as the preceding process.
- **Baselining:** The registry path `HKLM\System\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{B6D775EF-1436-4FE6-BAD3-9E436319E218}\Enabled` being set to `0` is not a routine administrative action and should be treated as an anomaly in any environment.
