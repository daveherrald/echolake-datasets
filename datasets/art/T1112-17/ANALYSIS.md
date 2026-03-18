# T1112-17: Modify Registry — Disable Windows Lock Workstation Feature

## Technique Context

T1112 (Modify Registry) is a defense evasion and persistence technique where adversaries modify the Windows registry to achieve their objectives. The specific test executed here disables the Windows Lock Workstation feature by setting the `DisableLockWorkstation` registry value to 1. This prevents users from locking their workstation (Win+L), potentially leaving systems accessible if users step away. Attackers use this technique to maintain access to compromised systems, prevent security-conscious users from locking their screens, and facilitate further malicious activities. Detection engineers typically focus on monitoring registry modifications to security-relevant keys, especially those affecting system policies, user controls, and security features.

## What This Dataset Contains

The dataset captures a complete execution chain starting with PowerShell test framework processes and culminating in the registry modification. The attack flow is clearly visible:

1. **PowerShell Execution**: Two PowerShell processes (PIDs 36356 and 21208) execute with command line `powershell.exe`, showing typical test framework activity with `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass`
2. **Process Chain**: PowerShell → cmd.exe → reg.exe with the command `reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableLockWorkstation /t REG_DWORD /d 1 /f`
3. **Registry Modification**: Sysmon EID 13 captures the actual registry write: `HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\policies\system\DisableLockWorkstation` set to `DWORD (0x00000001)`
4. **Process Telemetry**: Security 4688 events show the complete command lines, while Sysmon EID 1 events capture process creation for whoami.exe, cmd.exe, and reg.exe
5. **System Context**: All processes run as `NT AUTHORITY\SYSTEM` with full privileges (TokenElevationTypeDefault)

## What This Dataset Does Not Contain

The dataset is notably complete for this technique. The registry modification succeeded (exit status 0x0 for all processes), and all expected telemetry sources captured the activity. There are no missing Sysmon ProcessCreate events for the core attack chain, as cmd.exe and reg.exe are included in the sysmon-modular configuration's suspicious process patterns. The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy), with no malicious PowerShell script content, which is expected since this test uses PowerShell only as a launcher for the cmd/reg process chain.

## Assessment

This dataset provides excellent detection engineering value for T1112. The registry modification is captured with high fidelity across multiple data sources - Sysmon EID 13 shows the exact registry key and value, Security 4688 shows the command line, and process chains are complete. The technique executed successfully without Windows Defender interference, providing clean "success" telemetry rather than just "attempt" evidence. The data quality is particularly strong for building detections around registry policy modifications and process-based indicators. The combination of command-line arguments and registry event details makes this an ideal dataset for developing robust detection rules.

## Detection Opportunities Present in This Data

1. **Registry Policy Modification**: Monitor Sysmon EID 13 for writes to `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableLockWorkstation` or similar policy keys that disable security features

2. **Suspicious reg.exe Command Lines**: Detect Security 4688 events where reg.exe adds values to policy paths with arguments containing "DisableLockWorkstation", "Policies\System", or other security-disabling registry modifications

3. **Process Chain Analysis**: Alert on PowerShell → cmd.exe → reg.exe chains where reg.exe modifies security policy registry locations, particularly when the intermediate cmd.exe uses `/c` with registry modification commands

4. **Security Policy Registry Writes**: Build detections for any registry modifications under `*\Policies\System\*` paths that set values to 1 (enabled) for keys containing "Disable" in the name

5. **Cross-Source Correlation**: Correlate Sysmon registry events (EID 13) with corresponding process creation events (EID 1) and command-line logging (Security 4688) to validate that registry modifications came from expected processes rather than direct API calls
