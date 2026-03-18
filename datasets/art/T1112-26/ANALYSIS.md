# T1112-26: Modify Registry — Activate Windows NoPropertiesMyDocuments Group Policy Feature

## Technique Context

T1112 (Modify Registry) is a fundamental technique used by adversaries to achieve persistence, defense evasion, and system configuration changes on Windows systems. Attackers frequently modify registry keys to disable security features, establish persistence mechanisms, or alter system behavior to support their operations. The specific variant in this test—activating the NoPropertiesMyDocuments Group Policy feature—demonstrates how adversaries can use registry modifications to disable user interface elements, potentially hiding evidence of their activities or preventing users from accessing certain system properties.

The detection community focuses heavily on monitoring registry modifications to sensitive keys, particularly those related to security settings, startup locations, and system policies. Registry monitoring is considered one of the most reliable detection methods for Windows-based threats, as most persistence and configuration changes require registry modifications that can be tracked through native Windows logging capabilities.

## What This Dataset Contains

This dataset captures a straightforward registry modification executed through PowerShell calling cmd.exe, which then invokes reg.exe. The complete process chain is visible in Security event 4688:

- PowerShell (PID 36584) spawns cmd.exe with command line: `"cmd.exe" /c reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoPropertiesMyDocuments /t REG_DWORD /d 1 /f`
- cmd.exe (PID 4860) then spawns reg.exe with the actual registry modification command: `reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoPropertiesMyDocuments /t REG_DWORD /d 1 /f`

Sysmon captures the process creation events for both cmd.exe (EID 1) and reg.exe (EID 1), tagged with appropriate MITRE technique annotations (T1059.003 for Windows Command Shell and T1012 for Query Registry). The PowerShell events in the dataset contain only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) and do not show the actual registry modification command being executed within PowerShell.

All processes exit cleanly with status 0x0, indicating successful execution of the registry modification.

## What This Dataset Does Not Contain

The dataset lacks the actual registry change event itself—there are no Sysmon EID 13 (RegistryEvent: Value Set) events that would directly show the registry value being created or modified. This is likely due to the sysmon-modular configuration not including registry monitoring rules for this specific registry path. The absence of these events significantly limits the dataset's utility for demonstrating comprehensive registry modification detection.

Additionally, there are no process creation events for the initial PowerShell process that executed the technique, as the sysmon-modular configuration uses include-mode filtering for ProcessCreate events and may not have captured the parent PowerShell process launch.

## Assessment

This dataset provides moderate utility for detection engineering, primarily showcasing process-based detection opportunities rather than direct registry monitoring. While it demonstrates the typical process execution patterns used in registry modifications (PowerShell → cmd.exe → reg.exe), the absence of actual registry change events limits its value for building comprehensive T1112 detections. The dataset is most valuable for detecting the specific combination of command-line utilities used to perform registry modifications, but detection engineers would need additional registry monitoring capabilities to build complete coverage for this technique.

## Detection Opportunities Present in This Data

1. **Registry tool execution via command shell** - Monitor for reg.exe execution with "add" operations targeting policy-related registry paths, particularly under CurrentVersion\Policies
2. **Suspicious cmd.exe command lines** - Detect cmd.exe processes with /c parameter followed by registry modification commands
3. **PowerShell spawning system utilities** - Alert on PowerShell processes creating cmd.exe or reg.exe child processes
4. **Group Policy registry path targeting** - Monitor process command lines containing references to Windows\CurrentVersion\Policies registry paths
5. **Process access to registry tools** - Sysmon EID 10 events show PowerShell accessing both whoami.exe and cmd.exe processes, indicating potential process injection techniques used alongside registry modification
