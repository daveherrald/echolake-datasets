# T1112-14: Modify Registry — Disable Windows Shutdown Button

## Technique Context

T1112 (Modify Registry) involves adversaries making changes to the Windows Registry to alter system configurations, establish persistence, escalate privileges, or evade defenses. The detection community focuses heavily on monitoring registry modifications to sensitive keys, particularly those affecting security policies, system configurations, and startup programs.

This specific test disables the Windows shutdown button by modifying the `shutdownwithoutlogon` registry value in `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`. When set to 0, this prevents users from shutting down the system without logging in first. While this particular modification has limited tactical value for most adversaries, it demonstrates the broader category of policy manipulation through registry changes that could be used for denial of service or system control purposes.

## What This Dataset Contains

The dataset captures a complete execution chain showing PowerShell launching a command shell to execute the registry modification:

**Process Chain:** The Security 4688 events show the full process execution sequence: `powershell.exe` → `cmd.exe /c reg add ...` → `reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v shutdownwithoutlogon /t REG_DWORD /d 0 /f`

**Registry Modification:** Sysmon Event ID 13 captures the actual registry write: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\shutdownwithoutlogon` set to `DWORD (0x00000000)` by the `reg.exe` process (PID 18696).

**Sysmon Process Creation:** Events show cmd.exe (PID 19860) and reg.exe (PID 18696) creation with full command lines, tagged with RuleName indicating T1059.003 (Windows Command Shell) and T1012 (Query Registry) techniques respectively.

**Process Access:** Sysmon Event ID 10 shows PowerShell accessing both child processes (whoami.exe and cmd.exe) with full access rights (0x1FFFFF), indicating normal parent-child process monitoring.

## What This Dataset Does Not Contain

The dataset lacks several important detection sources for comprehensive registry monitoring:

**No Registry Auditing:** Windows lacks native registry access auditing events (4656/4657/4663) because object access auditing is disabled in the audit policy configuration. This means we only see the Sysmon-captured registry write, not native Windows registry audit events.

**Missing Group Policy Events:** No events from the Group Policy operational logs that might show policy refresh or conflicts resulting from this registry change.

**No User Impact Telemetry:** The dataset doesn't capture any events showing the actual impact of the registry change on system behavior or user interface modifications.

## Assessment

This dataset provides excellent coverage for detecting registry-based policy manipulation through the combination of process creation telemetry and Sysmon registry monitoring. The Security 4688 events with command-line logging capture the complete attack narrative, while Sysmon Event ID 13 provides the specific registry modification details.

The process chain visibility is particularly strong, showing how adversaries often use command-line tools indirectly through scripting environments. However, the lack of native Windows registry auditing events represents a significant gap that many environments would need to address for comprehensive registry monitoring.

For detection engineering, this dataset demonstrates the critical importance of Sysmon registry monitoring when native Windows registry auditing is not enabled, which is the default configuration in many environments.

## Detection Opportunities Present in This Data

1. **Registry Policy Manipulation Detection** - Monitor Sysmon Event ID 13 for writes to `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\*` with focus on security-relevant values like `shutdownwithoutlogon`, `EnableLUA`, `ConsentPromptBehaviorAdmin`, etc.

2. **Command-Line Registry Tool Usage** - Alert on Security 4688 events showing `reg.exe` execution with `add` operations targeting sensitive registry paths, particularly when spawned by scripting engines like PowerShell.

3. **Process Chain Analysis** - Detect PowerShell spawning cmd.exe which then spawns reg.exe, especially when the command line contains registry modification operations targeting system policy keys.

4. **Indirect Registry Modification** - Monitor for registry tools (reg.exe, powershell.exe with registry cmdlets) being invoked through command shells rather than directly, which may indicate scripted or automated attacks.

5. **System Policy Tampering** - Create specific detections for modifications to the Policies\System registry hive, as changes here often affect critical security controls and system behavior.

6. **Registry Tool Parent Process Analysis** - Flag reg.exe execution when the parent process is not a typical administrative tool or when launched from unexpected directories or contexts.
