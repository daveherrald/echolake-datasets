# T1547.001-12: Registry Run Keys / Startup Folder — HKCU Policy Settings Explorer Run Key

## Technique Context

T1547.001 covers Registry Run Keys and Startup Folder persistence. This test exercises a specific Run key path that is distinct from the canonical `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` key: the Group Policy-administered path `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`. Values written to this path cause the referenced executable to run at logon for the current user, exactly like the standard Run key, but with an important difference in detection coverage.

The `Policies\Explorer\Run` path is associated with Group Policy software installation and execution policy. In environments where GPO-driven software deployment is common, values under `Policies\Explorer\Run` may be expected and less scrutinized. Many EDR configurations and baseline detection rules monitor `HKLM\...\Run` and `HKCU\...\Run` specifically, without extending coverage to the `Policies\` subtree variants.

The test conditionally creates the required keys if they do not exist, then writes a value named `atomictest` pointing to `C:\Windows\System32\calc.exe`. The use of `New-Item` with a `Test-Path` guard ensures idempotent execution.

In the defended variant, this test produced 47 Sysmon events (vs 27 here). The difference is substantial — 20 additional events in the defended environment — and reflects Defender's monitoring overhead adding EID 7 DLL load events and EID 10 process access events for its scanning activity.

## What This Dataset Contains

The dataset spans 5 seconds (2026-03-17 17:09:10–17:09:15 UTC) on ACME-WS06 (`acme.local`), executing as `NT AUTHORITY\SYSTEM`.

**Sysmon (27 events — Event IDs 1, 7, 10, 11, 13, 17):**

Sysmon EID 1 (ProcessCreate, 3 events):

1. `whoami.exe` — test framework context check, tagged `technique_id=T1033`
2. `powershell.exe` — tagged `technique_id=T1083`, full command line:
   ```
   "powershell.exe" & {if (!(Test-Path -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\")){
     New-Item -ItemType Key -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\"
   }
   if (!(Test-Path -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\")){
     New-Item -ItemType Key -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\"
   }
   Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" -Name "atomictest" -Value "C:\Windows\System32\calc.exe"}
   ```
3. `whoami.exe` — second context check

Sysmon EID 13 (RegistrySetValue, 1 event) tagged `technique_id=T1547.001,technique_name=Registry Run Keys / Start Folder`:
- `TargetObject: HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\atomictest`
- `Details: C:\Windows\System32\calc.exe`
- Set by `powershell.exe` (PID 5548) as `NT AUTHORITY\SYSTEM`

This is the persistence artifact. The key path `Policies\Explorer\Run` is confirmed in the `TargetObject` field, using the HKU form (since the test runs as SYSTEM, `HKCU` maps to `HKU\.DEFAULT`). The value name `atomictest` and the payload path `C:\Windows\System32\calc.exe` are both recorded.

Sysmon EID 11 (FileCreate, 1 event) records the PowerShell startup profile data file.

Sysmon EID 7 (ImageLoad, 17 events), EID 10 (ProcessAccess, 3 events), and EID 17 (PipeCreate, 2 events) are standard PowerShell initialization and test framework artifacts.

**Security (3 events — Event ID 4688):**

Three process creation events: `whoami.exe`, the `powershell.exe` with the full command line, and a second `whoami.exe`. The Security channel provides no additional unique information beyond what Sysmon EID 1 captures here — both record the `powershell.exe` command line identically.

**PowerShell (102 events — Event IDs 4103, 4104):**

ScriptBlock logging captures the full test and cleanup scripts. The `Set-ItemProperty` call targeting `Policies\Explorer\Run` and the cleanup `Remove-ItemProperty` for the `atomictest` value both appear in separate ScriptBlock entries.

## What This Dataset Does Not Contain

- **No logon execution:** The test registers the Run key value but does not log off and back on. `calc.exe` is not executed from the registered path during this test window.
- **No registry key creation events (EID 12):** The `New-Item` calls for the `Explorer` and `Explorer\Run` keys produce key creation events, but these are not captured in the available samples. The EID breakdown confirms 1 EID 13 event; EID 12 events for the key creations are not in the sample pool.
- **Cleanup removes the artifact:** The ART cleanup script calls `Remove-ItemProperty` to delete the `atomictest` value. The cleanup itself is captured in PowerShell EID 4104 but the corresponding EID 13 or EID 12 deletion event is not in the samples.

## Assessment

This dataset provides a clean, direct record of the `Policies\Explorer\Run` persistence pattern. The Sysmon EID 13 event is the most actionable artifact: it captures the exact registry path, value name, and payload in a single event. The PowerShell command line in EID 1 and EID 4104 provides corroborating context.

The significant difference between undefended (27) and defended (47) Sysmon events — 20 additional events when Defender is present — suggests that Defender's scanning activity adds measurable telemetry overhead to this technique's execution even when it does not block it. The undefended variant is cleaner for training detection models against the technique itself without Defender noise.

## Detection Opportunities Present in This Data

- **Sysmon EID 13:** `TargetObject` matching `HKU\*\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\*` with any value set to an executable path. Writes to `Policies\Explorer\Run` are not expected in normal administrative operations and warrant immediate investigation.
- **Sysmon EID 1 / Security EID 4688:** `powershell.exe` command line containing `Set-ItemProperty` targeting `HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`. The full path in a `Set-ItemProperty` call is a specific enough indicator to distinguish from legitimate use.
- **PowerShell EID 4104:** `Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" -Name <name> -Value <path>` in a ScriptBlock. The combination of the `Policies` subtree, the `Run` key, and a value pointing to an executable path is actionable.
- **Composite:** The pattern of `New-Item -ItemType Key -Path "HKCU:\...\Policies\Explorer"` followed by `New-Item ... Policies\Explorer\Run` followed by `Set-ItemProperty ... -Name "atomictest" -Value "...\.exe"` in a single ScriptBlock represents the creation of a previously non-existent Run key location followed by registration — a sequence specific to establishing persistence in a clean environment.
