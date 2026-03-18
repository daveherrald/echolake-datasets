# T1112-61: Modify Registry — Activities To Disable Secondary Authentication Detected By Modified Registry Value.

## Technique Context

T1112: Modify Registry is a fundamental technique used by attackers to alter Windows registry keys and values for defense evasion and persistence. In this specific case, the test targets the Windows Hello for Business secondary authentication system by setting the `AllowSecondaryAuthenticationDevice` registry value to 0, effectively disabling multi-factor authentication features. This technique is particularly concerning as it weakens authentication security posture while appearing as a legitimate configuration change.

Attackers commonly modify registry settings to disable security features, establish persistence through Run keys, alter system configurations, or hide their presence. The detection community focuses heavily on monitoring registry modifications to sensitive security-related keys, unusual process chains writing to registry locations, and changes to authentication or security policy settings.

## What This Dataset Contains

This dataset captures the complete execution chain for disabling secondary authentication through registry modification:

**Process Chain:**
- PowerShell parent process (`powershell.exe`, PID 43036) spawns `whoami.exe` for reconnaissance
- PowerShell then spawns `cmd.exe` with command: `"cmd.exe" /c reg add "HKLM\SOFTWARE\Policies\Microsoft\SecondaryAuthenticationFactor" /v "AllowSecondaryAuthenticationDevice" /t REG_DWORD /d 0 /f`
- `cmd.exe` spawns `reg.exe` with the actual registry modification command: `reg add "HKLM\SOFTWARE\Policies\Microsoft\SecondaryAuthenticationFactor" /v "AllowSecondaryAuthenticationDevice" /t REG_DWORD /d 0 /f`

**Security Event Coverage:**
- Security 4688 events capture all process creations with full command lines
- Security 4689 events show clean process exits (exit code 0x0)
- Security 4703 shows PowerShell token privilege adjustment with high-privilege tokens

**Sysmon Coverage:**
- Sysmon EID 1 captures process creation for `whoami.exe`, `cmd.exe`, and `reg.exe` with full command line details and process relationships
- Sysmon EID 10 shows PowerShell accessing child processes with full access rights (0x1FFFFF)
- Sysmon EID 7 events capture .NET runtime and PowerShell module loading
- Sysmon EID 17 shows PowerShell named pipe creation
- Sysmon EID 11 captures PowerShell profile file operations

## What This Dataset Does Not Contain

**Missing Registry Modification Evidence:** The dataset lacks direct registry modification telemetry. There are no Sysmon EID 13 (Registry value set) or EID 12 (Registry object added/deleted) events, indicating the sysmon-modular configuration doesn't monitor registry changes for this key path.

**Limited PowerShell Script Content:** The PowerShell channel contains only test framework boilerplate (`Set-StrictMode`, `Set-ExecutionPolicy Bypass`) without the actual registry modification commands, as the technique executes through `cmd.exe` and `reg.exe` rather than PowerShell cmdlets.

**No Object Access Auditing:** Windows object access auditing is disabled, so there are no 4663 events showing registry key access attempts that would complement the process-level telemetry.

## Assessment

This dataset provides excellent process-level visibility into registry modification attacks but lacks the registry-specific telemetry that would make it comprehensive. The Security 4688 events with command-line logging provide the strongest detection opportunity, capturing the exact registry path, value name, and data being set. Sysmon process creation events add valuable context about process relationships and execution flow.

The technique successfully executes without any blocking from Windows Defender, and all processes exit cleanly, indicating the registry modification completed successfully. However, without registry change events (Sysmon EID 13) or object access auditing, you cannot verify the actual registry write occurred or detect more subtle registry manipulation techniques that might not involve `reg.exe`.

## Detection Opportunities Present in This Data

1. **Command Line Detection for reg.exe with Secondary Authentication Keys** - Security 4688 and Sysmon EID 1 capture `reg.exe` with command line containing "SecondaryAuthenticationFactor" and "AllowSecondaryAuthenticationDevice"

2. **Process Chain Analysis** - PowerShell spawning cmd.exe spawning reg.exe represents a suspicious execution pattern for registry modifications, detectable through parent-child process relationships in Sysmon EID 1

3. **Registry Path Targeting** - Command lines containing "HKLM\SOFTWARE\Policies\Microsoft\SecondaryAuthenticationFactor" indicate targeting of Windows Hello authentication policies

4. **Process Access Pattern** - Sysmon EID 10 shows PowerShell accessing spawned processes with full access rights (0x1FFFFF), indicating potential process injection or manipulation capabilities

5. **Administrative Token Usage** - Security 4703 shows PowerShell with extensive system privileges (SeBackupPrivilege, SeRestorePrivilege, etc.) performing registry operations

6. **Authentication Policy Modification** - The specific value name "AllowSecondaryAuthenticationDevice" being set to 0 represents a clear attempt to disable multi-factor authentication features

7. **Indirect PowerShell Registry Modification** - PowerShell executing registry changes through cmd.exe/reg.exe instead of PowerShell registry cmdlets may indicate evasion of PowerShell-specific monitoring
