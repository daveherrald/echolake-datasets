# T1218-8: System Binary Proxy Execution — DiskShadow Command Execution

## Technique Context

T1218.008 System Binary Proxy Execution: DiskShadow represents a defense evasion technique where attackers abuse Windows' legitimate diskshadow.exe utility to proxy execution of malicious commands. DiskShadow is a legitimate Windows utility for managing Volume Shadow Copy Service (VSS) operations, but it includes a script execution capability that can be weaponized. When diskshadow.exe runs with the `-S` parameter followed by a script file path, it executes commands contained within that script file, effectively allowing arbitrary command execution through a signed Windows binary.

The detection community focuses on monitoring diskshadow.exe execution with script parameters, unusual process ancestry chains involving diskshadow, and file operations associated with VSS abuse. This technique is particularly concerning because it leverages a trusted Windows binary that may bypass application whitelisting solutions and generates process telemetry that appears legitimate at first glance.

## What This Dataset Contains

This dataset captures a complete DiskShadow proxy execution sequence initiated through PowerShell. The technique manifests in Security event 4688 showing PowerShell spawning with the command line: `"powershell.exe" & {C:\Windows\System32\diskshadow.exe -S C:\AtomicRedTeam\atomics\T1218\src\T1218.txt}`. Sysmon event 1 confirms this with ProcessId 26000 and the full command line showing DiskShadow being invoked with the `-S` script parameter.

The PowerShell script block logging in event 4104 reveals the exact execution pattern: `& {C:\Windows\System32\diskshadow.exe -S C:\AtomicRedTeam\atomics\T1218\src\T1218.txt}`, demonstrating how PowerShell is used as the initial execution vector to invoke DiskShadow with a script file.

The dataset shows the complete process hierarchy with Security events 4688 and Sysmon events capturing PowerShell process creation (PID 26000) spawned from a parent PowerShell process (PID 16464). A whoami.exe process (PID 20488) is also created and captured by both Security 4688 and Sysmon 1, suggesting the DiskShadow script contained system discovery commands.

Sysmon process access events (EID 10) show PowerShell accessing both the whoami.exe process and another PowerShell process with full access rights (0x1FFFFF), indicating process injection techniques or process manipulation activities.

## What This Dataset Does Not Contain

Critically, this dataset lacks the actual diskshadow.exe process creation events. Neither Security 4688 nor Sysmon 1 events show diskshadow.exe being spawned, despite the PowerShell command line clearly attempting to execute it. This suggests that Windows Defender's real-time protection blocked the diskshadow.exe execution before the process could be created, preventing the System Binary Proxy Execution technique from completing successfully.

The dataset also lacks any file system events showing the DiskShadow script file (`C:\AtomicRedTeam\atomics\T1218\src\T1218.txt`) being accessed or read, which would normally occur during legitimate DiskShadow script execution. No VSS-related operations or shadow copy activities are present in the telemetry.

Network connections, registry modifications, or other side effects typically associated with successful DiskShadow script execution are absent, confirming that the technique was blocked at the initial process creation stage.

## Assessment

This dataset provides excellent telemetry for detecting DiskShadow proxy execution attempts, even when they are blocked by endpoint protection. The Security 4688 and PowerShell 4104 events clearly capture the malicious intent and command structure, making this dataset valuable for building detections that focus on execution attempts rather than successful technique completion.

The process telemetry quality is high, with complete command lines, process ancestry, and timing information. However, the dataset's limitation lies in not capturing successful technique execution, which limits its utility for understanding the full attack chain and developing detections for post-execution artifacts.

The PowerShell telemetry is particularly strong, capturing both the script block content and command invocation details that would be essential for detection engineering focused on the initial attack vector.

## Detection Opportunities Present in This Data

1. **DiskShadow Script Parameter Detection** - Monitor Security 4688 and Sysmon 1 for diskshadow.exe processes spawned with `-S` parameter indicating script execution mode.

2. **PowerShell DiskShadow Invocation** - Alert on PowerShell script blocks (4104) containing diskshadow.exe execution with script parameters, particularly using the `& {}` invocation syntax.

3. **Suspicious Process Command Line Patterns** - Detect command lines containing "diskshadow.exe -S" followed by file paths, especially in non-standard locations like AtomicRedTeam directories.

4. **PowerShell Parent-Child Process Relationships** - Monitor for PowerShell processes spawning other PowerShell instances with DiskShadow-related command lines, indicating potential proxy execution chains.

5. **Blocked Process Execution Correlation** - Correlate PowerShell command lines containing diskshadow.exe with the absence of corresponding diskshadow.exe process creation events, indicating blocked execution attempts.

6. **Process Access Anomalies** - Alert on PowerShell processes accessing other processes with full rights (0x1FFFFF) in conjunction with DiskShadow execution attempts, suggesting process manipulation techniques.

7. **System Discovery Command Correlation** - Monitor for whoami.exe or other discovery commands spawned in temporal proximity to DiskShadow execution attempts, indicating successful script execution or reconnaissance activities.
