# T1112-71: Modify Registry — Disable Windows Prefetch Through Registry

## Technique Context

T1112 (Modify Registry) is a defense evasion and persistence technique where attackers modify Windows registry keys to alter system behavior, disable security features, or establish persistence. Within this broad technique, disabling Windows Prefetch is a specific evasion tactic. Windows Prefetch improves application startup performance by pre-loading frequently used code and data, but it also creates forensic artifacts that investigators use to track program execution history.

Attackers disable Prefetch by setting the `EnablePrefetcher` registry value to 0 in `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters`. This prevents Windows from creating .pf files in `C:\Windows\Prefetch`, reducing forensic evidence of their activities. The detection community focuses on monitoring registry modifications to security-relevant keys, process creation for registry modification tools like reg.exe, and command-line arguments containing suspicious registry paths.

## What This Dataset Contains

This dataset captures a complete execution chain for disabling Windows Prefetch through registry modification:

**Process Chain**: PowerShell spawns cmd.exe, which spawns reg.exe to perform the registry modification:
- Security 4688 shows cmd.exe creation: `"cmd.exe" /c reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d 0 /f`
- Security 4688 shows reg.exe creation: `reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d 0 /f`

**Sysmon Process Events**: Three Sysmon EID 1 events capture the process creations - whoami.exe (PID 37908), cmd.exe (PID 22400), and reg.exe (PID 2880) with full command lines and parent-child relationships.

**Process Termination**: Security 4689 events document clean exits (status 0x0) for all spawned processes, indicating successful execution.

**PowerShell Activity**: The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) without the actual technique script content.

**Process Access Events**: Sysmon EID 10 shows PowerShell accessing child processes with full access (0x1FFFFF), typical of process spawning operations.

## What This Dataset Does Not Contain

**Registry Modification Events**: No Sysmon EID 13 (RegistryEvent - Value Set) events are present, indicating the sysmon-modular configuration doesn't monitor the specific registry key being modified. This is a significant gap for detecting this technique.

**Missing PowerShell Script Content**: The actual PowerShell commands that initiated the registry modification aren't captured in script block logging, only the test framework setup commands.

**File System Activity**: No file creation events related to the registry modification process beyond PowerShell profile updates.

**Network Activity**: No network connections associated with this local registry modification technique.

## Assessment

This dataset provides good process-level telemetry for detecting the technique but has a critical gap in registry monitoring. The Security and Sysmon process creation events clearly show the suspicious command line patterns and process relationships that are hallmarks of this technique. However, the absence of registry modification events means you cannot confirm the technique actually succeeded - you only see the attempt.

The data quality is strong for building detections around:
1. Process creation patterns (PowerShell → cmd.exe → reg.exe)
2. Command-line analysis of registry modification attempts
3. Parent-child process relationships

The dataset would be significantly stronger with registry monitoring configured to capture the actual EnablePrefetcher value modification.

## Detection Opportunities Present in This Data

1. **Command Line Analysis**: Monitor for reg.exe command lines containing "EnablePrefetcher" and the specific PrefetchParameters registry path in Security 4688 or Sysmon EID 1 events.

2. **Process Chain Detection**: Alert on PowerShell spawning cmd.exe that subsequently spawns reg.exe, particularly when targeting system configuration registry keys.

3. **Registry Key Targeting**: Create alerts for any process attempting to modify the Memory Management\PrefetchParameters registry path, regardless of the specific value being set.

4. **Behavioral Pattern**: Monitor for reg.exe executions with "/f" (force) flag combined with DWORD type modifications to system-level HKLM keys.

5. **Parent Process Context**: Flag reg.exe executions where the parent process is cmd.exe and the grandparent is PowerShell, indicating potential scripted registry modification.

6. **Process Access Correlation**: Use Sysmon EID 10 events showing PowerShell accessing cmd.exe/reg.exe processes to identify the originating script context for registry modifications.
