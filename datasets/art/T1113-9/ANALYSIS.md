# T1113-9: Screen Capture — Windows Recall Feature Enabled - DisableAIDataAnalysis Value Deleted

## Technique Context

T1113 Screen Capture involves adversaries taking screenshots or capturing screen content to steal sensitive information displayed on victim systems. While traditional implementations use built-in utilities like screenshot tools or third-party applications, this specific test focuses on Windows Recall—a controversial AI-powered feature introduced in Windows 11 that continuously captures and analyzes screen content for search and retrieval purposes.

Windows Recall stores snapshots of user activity and uses AI to make screen content searchable. The feature is controlled by the `DisableAIDataAnalysis` registry value under `HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\WindowsAI`. This test simulates enabling Recall by first adding this registry value set to 0 (enabled), then deleting it entirely—both actions that could allow continuous screen capture functionality.

Detection engineers focus on monitoring registry modifications to Recall-related keys, process execution patterns involving registry manipulation tools, and PowerShell activity that targets Windows AI policies. This technique is particularly concerning because it enables persistent, automatic screen capture without obvious user indicators.

## What This Dataset Contains

This dataset captures registry manipulation designed to enable Windows Recall screen capture capabilities. The core technique execution is visible in Security event 4688 showing PowerShell launching with the command: `"powershell.exe" & {reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\WindowsAI" /v DisableAIDataAnalysis /t REG_DWORD /d 0 /f; reg delete "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\WindowsAI" /v DisableAIDataAnalysis /f}`.

The process chain shows powershell.exe (PID 12020) spawning a second PowerShell instance (PID 18008) that executes the registry manipulation commands. Two reg.exe processes are created: one to add the `DisableAIDataAnalysis` value set to 0 (PID 28796) with command line `"C:\Windows\system32\reg.exe" add HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\WindowsAI /v DisableAIDataAnalysis /t REG_DWORD /d 0 /f`, and another to delete the same value (PID 36224) with command line `"C:\Windows\system32\reg.exe" delete HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\WindowsAI /v DisableAIDataAnalysis /f`.

Sysmon provides detailed process creation events (EID 1) for whoami.exe, both PowerShell instances, and both reg.exe executions, along with process access events (EID 10) showing PowerShell accessing the spawned processes with full access rights (0x1FFFFF). PowerShell script block logging (EID 4104) captures the actual registry manipulation script: `{reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\WindowsAI" /v DisableAIDataAnalysis /t REG_DWORD /d 0 /f; reg delete "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\WindowsAI" /v DisableAIDataAnalysis /f}`.

## What This Dataset Does Not Contain

The dataset lacks the actual registry modification events that would typically be captured through Security event 4657 (registry value was modified) or Sysmon event 13 (registry value set). This suggests either the registry monitoring was not configured to capture changes to the specific WindowsAI policy key, or the modifications occurred in a way that bypassed standard registry auditing.

Since this test ran on Windows 11 Enterprise in a VM environment, the actual Windows Recall feature may not have been fully functional or installed, meaning we don't see telemetry from the Recall service itself starting, stopping, or beginning screen capture operations. There are no network connections, file system changes related to Recall databases, or service manipulation events that might accompany actual screen capture functionality.

The PowerShell channel contains mostly test framework boilerplate rather than detailed execution logs of the registry commands themselves, and we don't see any Windows Defender alerts or blocks despite this being a potentially suspicious registry modification pattern.

## Assessment

This dataset provides excellent telemetry for detecting registry-based Windows Recall manipulation attempts through process-focused detection strategies. The combination of Security 4688 command-line logging and Sysmon process creation events gives complete visibility into the attack chain, while PowerShell script block logging captures the exact commands executed.

The data quality is strong for building detections around process creation patterns, parent-child relationships, and command-line analysis. However, the absence of registry modification events limits the ability to create registry-focused detections that would complement the process-based approaches.

For Windows Recall-specific detection engineering, this dataset demonstrates how adversaries might enable screen capture functionality through policy manipulation, making it valuable for organizations deploying Windows 11 systems where Recall could be present.

## Detection Opportunities Present in This Data

1. PowerShell execution with command lines containing "WindowsAI" registry path and "DisableAIDataAnalysis" value manipulation
2. Sequential reg.exe executions targeting the same Windows AI policy registry key within short time intervals
3. Parent-child process relationships showing PowerShell spawning reg.exe with Windows Recall policy modifications
4. PowerShell script block logging capturing registry commands targeting Windows AI data analysis controls
5. Process access events showing PowerShell obtaining full access rights to reg.exe processes performing sensitive registry operations
6. Command-line patterns combining both add and delete operations against the same registry value in a single execution context
7. Registry tool usage (reg.exe) with "/f" force flags when targeting Windows AI policy configurations
8. PowerShell module loading patterns associated with registry manipulation activities in the context of Windows AI features
