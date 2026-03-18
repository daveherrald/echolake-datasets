# T1112-46: Modify Registry — Mimic Ransomware - Enable Multiple User Sessions

## Technique Context

T1112 Modify Registry represents a fundamental adversary capability to alter Windows registry values for persistence, defense evasion, or operational objectives. This specific test mimics ransomware behavior by enabling multiple Terminal Services sessions through the `AllowMultipleTSSessions` registry value. Real ransomware families often modify this setting to maintain multiple concurrent sessions during encryption operations, allowing them to maximize system access and encryption speed. Detection engineers focus on monitoring registry modifications to high-value keys, particularly those related to Windows logon mechanisms, security settings, and system configuration. The `HKCU\Software\Microsoft\Windows\CurrentVersion\Winlogon` key is especially critical as it controls user authentication and session behavior.

## What This Dataset Contains

This dataset captures a straightforward registry modification executed through PowerShell spawning cmd.exe and reg.exe. The process chain shows PowerShell (PID 12220) → cmd.exe (PID 17476) → reg.exe (PID 25140), with the specific command line `reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Winlogon /t REG_DWORD /v AllowMultipleTSSessions /d 1 /f`. Security events 4688 capture the full command-line arguments for both cmd.exe and reg.exe execution. Sysmon events provide process creation details with EID 1 events for whoami.exe, cmd.exe, and reg.exe, showing the complete attack flow. The dataset includes process access events (EID 10) showing PowerShell accessing both whoami.exe and cmd.exe with full access rights (0x1FFFFF). PowerShell script block logging captures only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass), with no actual malicious PowerShell content logged.

## What This Dataset Does Not Contain

Notably absent is any direct registry modification telemetry — neither Sysmon EID 12 (Registry key and value create and delete) nor EID 13 (Registry value set) events appear in the data. This absence suggests the sysmon-modular configuration may not include registry monitoring rules, or the specific registry hive (HKCU) operations aren't captured when executed by SYSTEM. The dataset lacks any Windows Defender blocking indicators, suggesting this registry modification was not flagged as malicious behavior. There are no application or system event log entries related to the registry change itself, and no process termination events are captured for the reg.exe process, indicating it completed successfully.

## Assessment

This dataset provides excellent process execution telemetry for detecting the behavioral pattern of registry modification through legitimate Windows utilities. The command-line arguments captured in Security 4688 events are particularly valuable, showing the exact registry key, value name (AllowMultipleTSSessions), data type (REG_DWORD), and value (1) being set. However, the absence of registry modification events significantly limits the dataset's utility for building comprehensive registry-focused detections. Detection engineers can use this data to identify suspicious process chains involving reg.exe with Terminal Services-related parameters, but cannot directly monitor the registry changes themselves. The clear process genealogy and preserved command lines make this dataset strong for behavioral detection but incomplete for comprehensive registry monitoring.

## Detection Opportunities Present in This Data

1. **Registry Utility Abuse Detection** - Alert on reg.exe execution with Winlogon-related registry keys in command line arguments, particularly focusing on `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Winlogon`

2. **Terminal Services Configuration Tampering** - Monitor for command lines containing "AllowMultipleTSSessions" parameter in reg.exe processes, especially when value is set to 1 (enabled)

3. **PowerShell-to-Registry Tool Process Chain** - Detect PowerShell spawning cmd.exe which subsequently spawns reg.exe, indicating potential scripted registry manipulation

4. **Suspicious Process Access Patterns** - Alert on PowerShell processes gaining full access (0x1FFFFF) to system utilities like whoami.exe and cmd.exe in rapid succession

5. **Registry Tool Parameter Analysis** - Flag reg.exe executions using the `/f` (force) parameter combined with `/t REG_DWORD` when targeting authentication-related registry locations

6. **SYSTEM Context Registry Modifications** - Monitor for reg.exe processes running under SYSTEM context targeting user-specific registry hives, which is anomalous behavior

7. **Ransomware-Associated Registry Keys** - Correlate reg.exe activity targeting Winlogon keys with other potential ransomware indicators, as this modification pattern is common in encryption malware
