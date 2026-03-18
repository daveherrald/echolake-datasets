# T1112-18: Modify Registry — Activate Windows NoDesktop Group Policy Feature

## Technique Context

T1112 (Modify Registry) is a fundamental technique used by attackers to alter system behavior, establish persistence, or evade detection through Windows registry modifications. The registry serves as a central configuration database for Windows systems, making it an attractive target for malicious activity.

This specific test (T1112-18) focuses on activating the Windows NoDesktop Group Policy feature by creating a registry entry that disables the desktop display. The detection community typically monitors for suspicious registry modifications using process creation events, registry access logs, and specific registry key patterns associated with policy manipulation. This technique is particularly notable because it can severely impact user experience by preventing normal desktop functionality.

## What This Dataset Contains

The dataset captures a complete execution chain showing PowerShell-initiated registry modification through cmd.exe and reg.exe:

**Process Chain**: The Security 4688 events show the full execution sequence: `powershell.exe` → `cmd.exe /c reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDesktop /t REG_DWORD /d 1 /f` → `reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDesktop /t REG_DWORD /d 1 /f`

**Sysmon Coverage**: Sysmon events 1 capture process creation for whoami.exe (PID 23176), cmd.exe (PID 22476), and reg.exe (PID 10524). The reg.exe execution shows the exact command line targeting the Explorer policies registry path.

**Process Access Events**: Sysmon event 10 captures PowerShell accessing both whoami.exe and cmd.exe processes with full access rights (0x1FFFFF), indicating potential process monitoring or injection preparation.

**PowerShell Activity**: The PowerShell channel contains only test framework boilerplate (Set-ExecutionPolicy Bypass, Set-StrictMode) with no technique-specific script content logged.

## What This Dataset Does Not Contain

The most critical missing element is **direct registry modification telemetry**. There are no Sysmon event 13 (Registry value set) or event 12 (Registry object added) events showing the actual registry write operation. This gap exists because the sysmon-modular configuration used in this environment may not be configured to monitor the specific registry path being modified, or the registry operation completed too quickly to be captured.

Additionally, the dataset lacks any Windows Defender behavioral detection alerts that might normally trigger on suspicious registry policy modifications, and there are no application or system events indicating the policy change took effect.

## Assessment

This dataset provides excellent **process execution telemetry** for detecting the attack methodology but falls short on the most crucial evidence - the actual registry modification. The process creation events with full command lines are high-fidelity indicators that clearly show malicious intent through the specific registry path and NoDesktop value being set.

The data quality is strong for process-based detection rules but would require additional registry monitoring configuration to provide complete visibility into T1112 activity. Security teams can reliably detect the attack pattern through command line analysis, but confirming successful registry modification would require supplementary data sources.

## Detection Opportunities Present in This Data

1. **Registry Modification via reg.exe**: Monitor Security 4688 events for reg.exe execution with command lines containing "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" and "NoDesktop"

2. **PowerShell-to-CMD Chain for Registry Operations**: Detect PowerShell spawning cmd.exe with /c parameter followed by registry modification commands, indicating potential evasion of direct PowerShell registry cmdlets

3. **Group Policy Tampering via Registry**: Alert on process creation events targeting Explorer policies registry paths, particularly when modifying desktop-related settings like NoDesktop

4. **System User Registry Manipulation**: Flag registry modification attempts by SYSTEM account targeting user policy paths, which is anomalous behavior for legitimate system operations

5. **Process Access Pattern**: Monitor Sysmon event 10 showing PowerShell accessing newly created processes (whoami.exe, cmd.exe) with full access rights, potentially indicating process monitoring for evasion purposes

6. **Living-off-the-Land Binary Abuse**: Detect reg.exe execution with suspicious parameters, especially when spawned from scripting environments like PowerShell through intermediate cmd.exe processes
