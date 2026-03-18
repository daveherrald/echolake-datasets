# T1548.002-2: Bypass User Account Control — PowerShell

## Technique Context

T1548.002 (Bypass User Account Control) describes methods by which adversaries circumvent the Windows UAC elevation prompt to run processes with higher privileges without triggering a consent dialog. The Event Viewer bypass is one of the oldest and most documented UAC bypass techniques. It exploits the fact that `eventvwr.exe` (the Event Viewer host process) is marked auto-elevate in its manifest and checks the registry key `HKCU\Software\Classes\mscfile\shell\open\command` before launching MMC. By writing an attacker-controlled binary path to that key under HKCU — which requires no elevated access — the attacker causes Event Viewer to silently execute their payload with full administrator privileges.

## What This Dataset Contains

The dataset captures a 6-second window of activity on ACME-WS02 (Windows 11 Enterprise, domain member of acme.local).

**PowerShell script block logging (4104)** preserves the exact attack payload:

```
{New-Item "HKCU:\software\classes\mscfile\shell\open\command" -Force
Set-ItemProperty "HKCU:\software\classes\mscfile\shell\open\command" -Name "(default)" -Value "C:\Windows\System32\cmd.exe" -Force
Start-Process "C:\Windows\System32\eventvwr.msc"}
```

**Module logging (4103)** records the individual cmdlet calls with parameter bindings: `New-Item` creating the registry key, `Set-ItemProperty` writing `cmd.exe` as the default handler for `.msc` files, and `Start-Process` launching Event Viewer.

**Sysmon Event 13** captures the registry write directly:
- `TargetObject: HKU\.DEFAULT\Software\Classes\mscfile\shell\open\command\(Default)`
- `Details: C:\Windows\System32\cmd.exe`
- Image: `powershell.exe`

**Sysmon Event 1** records `mmc.exe` being created (Event Viewer internally loads MMC to render the .msc snap-in), and `whoami.exe` running — the ART test's default verification step — from `powershell.exe` as parent.

**Security 4688** records process creation for `whoami.exe`, `powershell.exe`, and `mmc.exe`.

**Security 4703** records a token right adjustment on the SYSTEM logon session.

The PowerShell test framework generates boilerplate 4104 events with stub script blocks (`{ Set-StrictMode -Version 1; $_.PSMessageDetails }` and related error-formatting fragments) and repeated 4103 `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass` invocations. These are artifacts of the Invoke-AtomicRedTeam framework and are not part of the technique itself.

## What This Dataset Does Not Contain (and Why)

**No elevated `cmd.exe` spawned by `eventvwr.exe`**: The test executed as `NT AUTHORITY\SYSTEM` (Logon ID `0x3E7`), which is already maximally privileged. The bypass mechanism fired — the registry write and Event Viewer launch are both present — but the post-bypass payload (`cmd.exe`) has SYSTEM as its creator rather than an auto-elevated medium-integrity token being promoted. No `eventvwr.exe` process appears in Sysmon because the include-mode ProcessCreate filter does not match it; however, `mmc.exe` is visible in the Security log.

**No Sysmon Event 12 (registry key creation)**: The sysmon-modular configuration captures registry value sets (Event 13) but the initial `New-Item` creating the key may not match the configured include rules for Event 12.

**No object access events**: The audit policy has object access auditing disabled, so no file system or registry object access events appear.

**No UAC consent prompt or AppInfo service events**: These would appear in the Application/System logs, which are not collected in this dataset.

## Assessment

The technique executed successfully from a telemetry perspective: the registry hijack and Event Viewer launch both appear in the data. The execution context (SYSTEM) means the bypass did not produce a token integrity change visible in the data, but all the observable prerequisites and indicators are present. Windows Defender did not block this technique.

## Detection Opportunities Present in This Data

- **Sysmon Event 13**: Registry write to `HKCU\...\mscfile\shell\open\command` by any process other than trusted installers is a high-fidelity indicator of this specific bypass. The key path is well-known and easy to match.
- **Sysmon Event 1 / Security 4688**: `mmc.exe` spawned with `eventvwr.msc` ancestry, particularly when the creator is `powershell.exe` rather than an interactive shell, warrants investigation.
- **PowerShell 4104**: Script block content containing `eventvwr.msc` combined with `HKCU:\software\classes\mscfile` registry manipulation is highly indicative.
- **PowerShell 4103**: `New-Item` and `Set-ItemProperty` targeting the mscfile COM handler path, logged with full parameter bindings, are precise detection anchors.
- **Correlation**: Registry write to `mscfile\shell\open\command` followed within seconds by `mmc.exe` creation provides a reliable behavioral sequence for detection.
