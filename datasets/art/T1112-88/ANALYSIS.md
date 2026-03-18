# T1112-88: Modify Registry — Abusing MyComputer Disk Fragmentation Path for Persistence

## Technique Context

T1112 (Modify Registry) is a fundamental persistence and defense evasion technique where attackers modify Windows registry keys to maintain access or alter system behavior. This specific test (T1112-88) demonstrates an uncommon persistence method that abuses the Windows Explorer "MyComputer\DefragPath" registry key. When users access "This PC" properties and select the "Tools" tab for disk defragmentation, Windows executes the program specified in this registry path. This technique provides a legitimate-looking persistence mechanism that most defenders wouldn't monitor, as it requires user interaction with Windows Explorer's disk management interface to trigger. The attack modifies `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\DefragPath` to point to an attacker-controlled executable instead of the legitimate disk defragmentation tool.

## What This Dataset Contains

This dataset captures the complete execution chain of the registry modification technique. The attack begins with PowerShell execution, followed by cmd.exe spawning to execute the registry modification command. Security event 4688 shows the critical command: `"cmd.exe" /c reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\DefragPath" /t REG_EXPAND_SZ /d "%systemroot%\system32\notepad.exe" /f`. The child reg.exe process (PID 13048) executes with the expanded command line: `reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\DefragPath" /t REG_EXPAND_SZ /d "C:\Windows\system32\notepad.exe" /f`.

Sysmon captures the complete process tree: powershell.exe (PID 11340) → cmd.exe (PID 12552) → reg.exe (PID 13048). Event ID 1 shows reg.exe tagged with technique_id=T1012 (Query Registry), though this is actually modification rather than just querying. The PowerShell events contain only test framework boilerplate (Set-ExecutionPolicy Bypass), with no malicious script block content visible. All processes executed successfully with exit status 0x0, indicating the registry modification completed without errors.

## What This Dataset Does Not Contain

This dataset lacks the actual registry modification telemetry. Sysmon's registry monitoring events (Event IDs 12, 13, 14) are not present, likely due to the sysmon-modular configuration not capturing registry changes to this particular key path. Without registry events, you cannot directly observe the creation or modification of the DefragPath value. The dataset also doesn't show what happens when the persistence mechanism is triggered (i.e., when a user accesses disk defragmentation through Windows Explorer), as this requires user interaction that didn't occur during the test execution. No file system events show notepad.exe being accessed or executed as the payload.

## Assessment

This dataset provides excellent process execution telemetry for detecting the registry modification command but lacks the registry change events that would provide definitive proof of the technique's success. The Security 4688 events with command-line logging capture the complete attack methodology, making this data valuable for command-line based detections. However, the absence of Sysmon registry events significantly limits the dataset's utility for comprehensive registry monitoring detections. For detection engineering focused on process behavior and command-line patterns, this data is strong. For registry-focused detections of this specific persistence technique, additional registry monitoring configuration would be needed.

## Detection Opportunities Present in This Data

1. **Registry Modification Command Detection**: Monitor Security 4688 events for reg.exe executions with "DefragPath" in the command line, particularly targeting the MyComputer registry path.

2. **Suspicious Registry Key Targeting**: Alert on reg.exe processes modifying the specific registry path `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\DefragPath`.

3. **Process Chain Analysis**: Detect PowerShell → cmd.exe → reg.exe execution chains where the final command modifies Explorer-related registry keys.

4. **Registry Tool Abuse**: Monitor for reg.exe executions that create or modify registry values with REG_EXPAND_SZ type pointing to executable files outside standard system directories.

5. **Explorer Persistence Mechanism**: Create detections for modifications to any registry keys under the Explorer\MyComputer path, as these are rarely legitimately modified by administrative tools.

6. **Command Line Pattern Matching**: Search for command lines containing both "MyComputer" and "DefragPath" strings, as this combination indicates potential abuse of this specific persistence technique.
