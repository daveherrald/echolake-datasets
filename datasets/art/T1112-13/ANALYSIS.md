# T1112-13: Modify Registry — Disable Windows Notification Center

## Technique Context

T1112 (Modify Registry) is a foundational technique where adversaries alter Windows registry settings to achieve persistence, defense evasion, or system configuration changes. The technique is particularly attractive to attackers because registry modifications often persist across reboots and can fundamentally alter system behavior without requiring ongoing process execution.

This specific test focuses on disabling the Windows Notification Center by creating the `DisableNotificationCenter` registry value under `HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Explorer`. While this particular modification might seem benign, it represents a broader category of defense evasion techniques where attackers disable security notifications, logging mechanisms, or user-facing security features to operate with reduced visibility.

The detection community typically focuses on monitoring registry modifications to security-relevant keys, the tools used to make these changes (reg.exe, PowerShell, direct API calls), and the process lineage that leads to registry writes. This technique demonstrates a straightforward command-line approach using the built-in reg.exe utility.

## What This Dataset Contains

The dataset captures a complete execution chain starting with PowerShell and culminating in a registry modification. The key telemetry shows:

**Process Creation Chain (Security 4688):**
- PowerShell process (PID 30572) spawns cmd.exe with command line: `"cmd.exe" /c reg add HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Explorer /v DisableNotificationCenter /t REG_DWORD /d 1 /f`
- cmd.exe (PID 43420) spawns reg.exe with command line: `reg add HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Explorer /v DisableNotificationCenter /t REG_DWORD /d 1 /f`

**Sysmon Process Creation (EID 1):**
- whoami.exe execution for system discovery
- cmd.exe execution with full command line showing the registry modification intent
- reg.exe execution with the specific registry key, value name (`DisableNotificationCenter`), type (`REG_DWORD`), data (`1`), and force flag (`/f`)

**Process Access Events (Sysmon EID 10):**
- PowerShell accessing both whoami.exe and cmd.exe processes with full access rights (0x1FFFFF), indicating process monitoring or injection detection capabilities

**PowerShell Telemetry:** The PowerShell events contain only test framework boilerplate (`Set-StrictMode`, `Set-ExecutionPolicy Bypass`) rather than the actual technique implementation, suggesting the test used PowerShell to invoke external commands rather than native PowerShell registry modification cmdlets.

## What This Dataset Does Not Contain

The dataset lacks direct registry modification telemetry. Notably absent are:

- **Registry write events** - No Sysmon EID 13 (Registry value set) events capture the actual registry modification, likely due to the sysmon-modular configuration not monitoring HKCU policy keys or reg.exe not triggering the configured registry monitoring rules
- **Registry access events** - No Sysmon EID 12 (Registry object access and creation) events showing key creation or access
- **PowerShell script content** - The actual PowerShell commands that initiated this chain are not captured in script block logging, only execution policy changes

This means while we can see the process execution chain and intent through command lines, we cannot directly observe the registry modification itself taking place, which would be crucial for comprehensive detection coverage.

## Assessment

This dataset provides good coverage for **process-based detection** of registry modification attempts but falls short on **registry-focused detection**. The command-line evidence is excellent and shows clear malicious intent, making it valuable for detecting the use of reg.exe for policy modifications. However, the absence of actual registry write telemetry means you cannot build detections that trigger on the registry change itself.

The process lineage is well-documented through both Security and Sysmon channels, providing multiple detection opportunities. The combination of PowerShell spawning cmd.exe spawning reg.exe with policy-related registry modifications is a strong behavioral indicator.

For building comprehensive T1112 detections, this dataset would need to be supplemented with registry monitoring configuration that captures the actual HKCU policy modifications.

## Detection Opportunities Present in This Data

1. **Process command line detection** - Monitor for reg.exe execution with "add" operations targeting policy registry paths (`HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Explorer`)

2. **Registry tool abuse** - Detect reg.exe processes with parent processes of cmd.exe or PowerShell, especially when modifying system policy keys

3. **Process creation chain anomaly** - Alert on PowerShell → cmd.exe → reg.exe execution chains, particularly when the reg.exe operation targets security-relevant registry locations

4. **Notification center tampering** - Specifically monitor for the `DisableNotificationCenter` registry value creation as an indicator of defense evasion attempts

5. **Policy modification via command line** - Detect any command-line registry operations that target the `\SOFTWARE\Policies\` registry path, which contains security and system policy configurations

6. **Cross-process access patterns** - Monitor for PowerShell processes gaining full access (0x1FFFFF) to subsequently spawned command-line tools, which may indicate process injection or monitoring evasion techniques
