# T1548.002-23: Bypass User Account Control — UAC Bypass with WSReset Registry Modification

## Technique Context

T1548.002 (Bypass User Account Control) includes techniques that exploit auto-elevate Windows components. The WSReset bypass leverages `WSReset.exe` — the Windows Store reset utility — which is marked auto-elevate in its manifest and reads a command handler from a specific HKCU registry path before executing. By creating the key `HKCU\Software\Classes\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\Shell\open\command` with a `DelegateExecute` value (which triggers the COM handler path) and a default value pointing to an attacker payload, then launching `WSReset.exe`, the attacker causes the auto-elevated process to silently execute their chosen command without a UAC prompt. This is a well-documented bypass that works on standard Windows 10/11 installations.

## What This Dataset Contains

The dataset captures approximately 6 seconds of activity on ACME-WS02 (Windows 11 Enterprise, domain member of acme.local).

**PowerShell script block logging (4104)** records the complete attack payload:

```
{New-Item HKCU:\Software\Classes\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\Shell\open\command -Force | Out-Null
New-ItemProperty -Path HKCU:\Software\Classes\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\Shell\open\command -Name "DelegateExecute" -Value "" -Force | Out-Null
Set-ItemProperty -Path HKCU:\Software\Classes\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\Shell\open\command -Name "(default)" -Value "C:\Windows\System32\cmd.exe /c start cmd.exe" -Force -ErrorAction SilentlyContinue | Out-Null
$Process = Start-Process -FilePath "C:\Windows\System32\WSReset.exe" -WindowStyle Hidden}
```

**PowerShell 4103 module logging** records each cmdlet with full parameter bindings:
- `New-Item` creating the registry key path with `-Force`
- `New-ItemProperty` setting `DelegateExecute` to empty string (required to trigger COM handler lookup)
- `Set-ItemProperty` writing `C:\Windows\System32\cmd.exe /c start cmd.exe` as the default handler
- `Start-Process` launching `WSReset.exe` with `-WindowStyle Hidden`

**Sysmon Event 13** (registry value set) captures both writes:
- `TargetObject: HKU\.DEFAULT\Software\Classes\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\Shell\open\command\DelegateExecute` → `(Empty)`
- `TargetObject: HKU\.DEFAULT\Software\Classes\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\Shell\open\command\(Default)` → `C:\Windows\System32\cmd.exe /c start cmd.exe`

**Sysmon Event 1** captures `WSReset.exe` with an explicit MITRE rule annotation:
- `RuleName: technique_id=T1548.002,technique_name=Bypass User Access Control`
- `Image: C:\Windows\System32\WSReset.exe`
- `CommandLine: "C:\Windows\System32\WSReset.exe"`
- Parent: `powershell.exe`

This is the only T1548.002 dataset in this series where the Sysmon process create rule directly tags the bypass binary itself.

**Security 4688**: Records `whoami.exe`, `powershell.exe`, `WSReset.exe`, and an additional process creation.

## What This Dataset Does Not Contain (and Why)

**No `cmd.exe` spawned by WSReset**: The dataset contains `WSReset.exe` launching, but no subsequent `cmd.exe` from it. The test ran as SYSTEM (already fully privileged), so the auto-elevate mechanism is not invoked in the traditional sense — the registry keys were written under `HKU\.DEFAULT` (the SYSTEM default hive) rather than a medium-integrity user's HKCU. An interactive medium-integrity user would be required to demonstrate the actual privilege elevation outcome.

**No Sysmon Event 12 (registry key creation)**: The `New-Item` call is not captured as Event 12; only the subsequent value sets (Event 13) appear. This is consistent across the registry-modification tests in this series.

**No Security object access auditing**: Object access is not enabled in the audit policy, so no registry access audit events accompany the Sysmon data.

## Assessment

The WSReset bypass technique executed fully — the registry writes are present, `WSReset.exe` launched, and Sysmon tagged both the registry writes and the process create with T1548.002 annotations. This is one of the more telemetry-rich tests in the series. The sysmon-modular include-mode filter explicitly covers `WSReset.exe` as a bypass indicator, demonstrating that this technique is well-known and specifically monitored.

## Detection Opportunities Present in This Data

- **Sysmon Event 13**: Registry write to `HKCU\...\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\Shell\open\command` — particularly the `DelegateExecute` value — is a high-fidelity indicator. This specific AppX GUID is hardcoded to WSReset's COM server lookup.
- **Sysmon Event 1**: `WSReset.exe` spawned by `powershell.exe` or any non-system process, especially with `-WindowStyle Hidden`, is directly flagged by the sysmon-modular rule set and annotated as T1548.002.
- **PowerShell 4104**: Script block containing `AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2` is a near-unique string identifying this specific bypass. Combined with `DelegateExecute` and `WSReset`, it is highly specific.
- **PowerShell 4103**: Parameter bindings showing `DelegateExecute` being set to empty and a command payload being written to `(default)` in the AppX COM handler path are precise detection anchors.
- **Behavioral sequence**: Registry key creation → DelegateExecute write → default value write → WSReset.exe launch, all within 400ms, is a reliable detection chain that is very unlikely to occur in legitimate use.
