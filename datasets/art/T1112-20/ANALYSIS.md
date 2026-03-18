# T1112-20: Modify Registry — Activate Windows NoFind Group Policy Feature

## Technique Context

T1112 (Modify Registry) is a versatile technique used by attackers for both defense evasion and persistence. Adversaries modify Windows registry keys to disable security features, hide their presence, maintain persistence, or alter system behavior. The technique is fundamental to many attack scenarios because the Windows registry controls virtually every aspect of the operating system's functionality.

This specific test activates the Windows "NoFind" Group Policy feature by setting `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoFind` to 1. This registry modification disables the Windows Search/Find functionality in Explorer, which could be used by attackers to prevent users from easily searching for and discovering malicious files or system changes. The detection community focuses on monitoring registry modifications to policy-related keys, especially those that disable security features or alter user interface capabilities.

## What This Dataset Contains

This dataset captures a successful registry modification executed via PowerShell and the Windows `reg.exe` utility. The core technique evidence appears in multiple channels:

**Security Channel (Event ID 4688):** Process creation events show the full command line execution chain:
- PowerShell spawning cmd.exe: `"cmd.exe" /c reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoFind /t REG_DWORD /d 1 /f`
- cmd.exe spawning reg.exe with the same registry modification command

**Sysmon Channel:** ProcessCreate events (EID 1) capture the same process chain with additional context:
- cmd.exe process (PID 24308) with full command line including the registry modification
- reg.exe process (PID 11036) executing the actual registry add operation
- Process relationships clearly showing PowerShell → cmd.exe → reg.exe execution chain

**PowerShell Channel:** Contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy) - no evidence of the actual registry modification commands.

The dataset shows both processes exiting with status 0x0, indicating successful execution. Process access events (Sysmon EID 10) show PowerShell accessing the spawned child processes with full access rights (0x1FFFFF).

## What This Dataset Does Not Contain

This dataset lacks the most critical evidence for T1112 detection - actual registry modification events. While we see the process execution that performs the registry change, we don't see:

- **Registry modification events:** No Sysmon EID 13 (RegistryEvent) or Security EID 4657 (Registry value modification) events
- **Registry key creation events:** No Sysmon EID 12 events showing creation of new registry keys
- **Object access events:** The audit policy shows "object_access: none," so registry access auditing is disabled

This gap exists because the Sysmon configuration may not be monitoring this specific registry location, or Windows audit policy doesn't have registry auditing enabled. The dataset demonstrates a common challenge in registry-based attack detection - organizations often focus on process execution monitoring while missing the actual registry changes that constitute the technique's impact.

## Assessment

This dataset provides good process execution telemetry but poor coverage of the actual registry modification that defines T1112. The Security and Sysmon channels excel at capturing the command-line execution chain, making it valuable for detecting suspicious use of reg.exe with policy-related registry paths. However, the lack of registry modification events significantly limits its utility for comprehensive T1112 detection.

The process-based telemetry is high quality - Sysmon's ProcessCreate events include full command lines, process relationships, and file hashes. Security 4688 events provide complementary process creation coverage. This makes the dataset excellent for building detections around the delivery mechanism (suspicious reg.exe usage) but inadequate for detecting the actual technique impact (registry state changes).

For production environments, this dataset highlights the importance of enabling registry auditing through either Sysmon registry monitoring or Windows Security auditing of registry objects.

## Detection Opportunities Present in This Data

1. **Suspicious reg.exe command lines** - Monitor for reg.exe processes with command lines containing "Policies\Explorer" and policy-disabling values like "NoFind"

2. **PowerShell spawning registry utilities** - Detect PowerShell processes creating cmd.exe or reg.exe children, especially with registry modification commands

3. **Group Policy bypass attempts** - Alert on reg.exe operations targeting HKCU\Software\Microsoft\Windows\CurrentVersion\Policies paths

4. **Command line patterns for UI feature disabling** - Monitor for specific registry values like "NoFind", "NoSearch", or similar UI restriction keys being set to 1

5. **Process chain analysis** - Detect the PowerShell → cmd.exe → reg.exe execution pattern when combined with policy-related registry paths

6. **Behavioral clustering** - Combine reg.exe execution with file hashes and parent process analysis to identify potential attack tools using this technique
