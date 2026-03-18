# T1546-3: Event Triggered Execution — CommandProcessor AutoRun Key (HKCU, No Elevation)

## Technique Context

The per-user variant of the cmd.exe AutoRun persistence mechanism writes to `HKCU\Software\Microsoft\Command Processor\AutoRun`. Unlike the HKLM variant (T1546-2), no administrative privileges are required, making this accessible to any attacker who has a foothold under a standard user account. The payload runs every time that user opens a command prompt. In environments where users frequently invoke `cmd.exe` — through scripts, installers, or directly — this is a highly reliable execution trigger. Defenders monitor both HKLM and HKCU variants, noting that standard user accounts should not modify their own `Command Processor` key.

## What This Dataset Contains

The attack creates the HKCU key path if absent and sets the AutoRun value to `notepad.exe`. The process create chain and PowerShell script block are well-documented.

**Sysmon EID=1 (ProcessCreate):** A child PowerShell is spawned with the full HKCU variant attack script:
```
"powershell.exe" & {
  $path = "HKCU:\Software\Microsoft\Command Processor"
  if (!(Test-Path -path $path)){
    New-Item -ItemType Key -Path $path
  }
  New-ItemProperty -Path $path -Name "AutoRun" -Value "notepad.exe" -PropertyType "String"
}
```
This is executed as `NT AUTHORITY\SYSTEM` (the test framework context), so HKCU refers to the SYSTEM account's hive.

**PowerShell EID=4104 (ScriptBlock):** The full script block is captured verbatim, including the path check and conditional key creation before the value write. The `New-ItemProperty` call with `"AutoRun"` and `"notepad.exe"` is plainly visible.

**PowerShell EID=4103 (CommandInvocation):** `Test-Path`, `New-ItemProperty` invocations are logged with parameter bindings, confirming the path was checked and the write was attempted.

**Security 4688:** The child PowerShell process creation with the full inline script is recorded.

**Notable absence from Sysmon:** No EID=13 (RegistryValueSet) was generated for the `HKCU\Software\Microsoft\Command Processor\AutoRun` write. The sysmon-modular config's registry monitoring for `Command Processor\AutoRun` appears to match on the HKLM path but not the HKCU equivalent, or the HKCU write occurred under a session that Sysmon did not capture at the registry level. The PowerShell channel and Security 4688 are the primary evidence sources for this variant.

## What This Dataset Does Not Contain

- No Sysmon EID=13 for the HKCU AutoRun write — either a Sysmon config gap (HKLM-only rule) or a session mapping issue with HKCU under SYSTEM context.
- No Security 4657 — registry object auditing is not enabled.
- No trigger event showing `notepad.exe` actually executing when a subsequent cmd.exe session opens.
- No evidence of the key creation step (New-Item) in Sysmon registry events — EID=12 was also not generated.

## Assessment

Despite the absence of a Sysmon EID=13, this dataset demonstrates that the PowerShell channels (EID=4104 script block and EID=4103 module logging) provide strong coverage when Sysmon registry monitoring has a gap. The verbatim script block with `HKCU:\Software\Microsoft\Command Processor` and `AutoRun` is unambiguous. For organizations relying on Sysmon registry events as the primary persistence detection source, this dataset exposes a potential coverage gap for HKCU variants. Extending the Sysmon config to include `HKCU\Software\Microsoft\Command Processor\AutoRun` explicitly would close this gap. The dataset would also benefit from a follow-on cmd.exe launch demonstrating the AutoRun execution.

## Detection Opportunities Present in This Data

1. **PowerShell EID=4104 — script block containing `HKCU:\Software\Microsoft\Command Processor` with `AutoRun`**: The full attack text is captured in the script block log, providing a reliable detection source even when Sysmon registry monitoring misses the write.
2. **PowerShell EID=4103 — `New-ItemProperty` with parameter binding showing `Path = "HKCU:\Software\Microsoft\Command Processor"` and `Name = "AutoRun"`**: Module logging records the cmdlet invocation with all parameters, providing a structured detection signal.
3. **Sysmon EID=1 — child PowerShell with `Command Processor` and `AutoRun` in the command line**: The process create captures the complete inline script, enabling detection without any registry monitoring.
4. **Security 4688 — PowerShell child process with HKCU Command Processor path in command line**: Redundant detection channel for environments without Sysmon.
5. **Combined HKLM + HKCU monitoring**: Writing a detection that covers both `HKLM\SOFTWARE\Microsoft\Command Processor\AutoRun` and `HKCU\Software\Microsoft\Command Processor\AutoRun` in a single rule ensures neither variant evades registry-based detection.
