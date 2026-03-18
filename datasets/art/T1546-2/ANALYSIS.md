# T1546-2: Event Triggered Execution — CommandProcessor AutoRun Key (HKLM, Elevated)

## Technique Context

The Windows `cmd.exe` AutoRun registry value (`HKLM\SOFTWARE\Microsoft\Command Processor\AutoRun` and the per-user equivalent under HKCU) causes `cmd.exe` to execute a specified command every time a new command shell opens. This is a simple and effective persistence mechanism: because cmd.exe is invoked by hundreds of scripts, scheduled tasks, and applications, the attacker payload runs frequently without any user interaction. The HKLM variant requires elevation and affects all users; the HKCU variant can be set without elevation and affects only the current user. Detection focuses on writes to both hive locations and any command prompt sessions that immediately invoke an unexpected binary before the user's commands.

## What This Dataset Contains

The attack installs `notepad.exe` as a dummy payload via `New-ItemProperty` from an elevated PowerShell. All key evidence is present.

**Sysmon EID=1 (ProcessCreate):** A child PowerShell is spawned with the attack command:
`"powershell.exe" & {New-ItemProperty -Path "HKLM:\Software\Microsoft\Command Processor" -Name "AutoRun" -Value "notepad.exe" -PropertyType "String"}`

**Sysmon EID=13 (RegistryValueSet):** The write is captured with RuleName `technique_id=T1547.001,technique_name=Registry Run Keys / Start Folder` (sysmon-modular correctly patterns-matches this path):
- `Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- `TargetObject: HKLM\SOFTWARE\Microsoft\Command Processor\AutoRun`
- `Details: notepad.exe`

**Security 4688:** The child PowerShell with the full `New-ItemProperty` command line is logged, showing the HKLM path, value name `AutoRun`, and value `notepad.exe`.

The PowerShell module logging channel (EID=4103/4104) for the child PowerShell instance is not separately captured as technique content — the child is spawned by the test framework and the 4104 appears in the test framework's script block logging, not as a standalone block for the individual command.

## What This Dataset Does Not Contain

- No Sysmon EID=13 with the `HKCU` path — this test writes only to `HKLM`. The HKCU variant is covered in T1546-3.
- No Security 4657 — object-level registry auditing is not enabled.
- No cmd.exe execution triggered by the AutoRun key after installation. The dataset only shows the installation step, not the trigger (a cmd.exe launch that executes notepad.exe as a side effect).
- No evidence of cleanup — the AutoRun key removal is outside the collection window.

## Assessment

This is a clean, minimal dataset well-suited for writing a registry-based persistence detection rule. Sysmon EID=13 with the specific `HKLM\SOFTWARE\Microsoft\Command Processor\AutoRun` target path is the primary detection. The sysmon-modular config fires a RuleName of `T1547.001` (slightly misclassified — this is T1546, not T1547 — but the registry path match is correct and useful). The Security 4688 with the full command line provides an independent detection channel. The dataset would be strengthened by including a follow-on cmd.exe session that demonstrates the AutoRun payload executing, showing the persistence trigger in action alongside the installation.

## Detection Opportunities Present in This Data

1. **Sysmon EID=13 — write to `HKLM\SOFTWARE\Microsoft\Command Processor\AutoRun`**: Any write to this value is immediately suspicious. Legitimate AutoRun values are extremely rare; the presence of any non-empty value should be investigated.
2. **Sysmon EID=1 — PowerShell command line containing `New-ItemProperty` targeting `Command Processor\AutoRun`**: The PowerShell process create with this specific command line is a high-fidelity detection independent of registry monitoring.
3. **Security 4688 — process creation of child PowerShell with `HKLM:\Software\Microsoft\Command Processor` and `AutoRun` in the command line**: Useful in environments without Sysmon where Security audit is the primary telemetry source.
4. **Baseline monitoring for the AutoRun value existence**: On a clean host, this value is typically absent. Any creation of this value — regardless of the data — is worth alerting on.
5. **Correlation of PowerShell spawning child PowerShell + registry write to `Command Processor`**: The parent-child PowerShell pattern combined with the specific registry target allows sequencing the installation event for timeline analysis.
