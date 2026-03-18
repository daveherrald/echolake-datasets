# T1047-10: Windows Management Instrumentation — Application uninstall using WMIC

## Technique Context

T1047 Windows Management Instrumentation (WMI) represents one of the most versatile and commonly abused execution techniques in Windows environments. WMI provides a standardized interface for managing Windows systems through WQL queries and method calls, making it attractive to both legitimate administrators and attackers. The detection community focuses heavily on WMI execution patterns because of their dual-use nature — WMI can execute commands locally or remotely, query system information, and interact with installed software. This specific test demonstrates using WMI's product management capabilities to uninstall software, which could be used by attackers to remove security tools or clean up after an intrusion.

## What This Dataset Contains

This dataset captures a complete WMI-based application uninstall attempt with rich telemetry across multiple event sources. The core execution chain shows PowerShell (PID 42180) spawning cmd.exe with the command `"cmd.exe" /c wmic /node:"127.0.0.1" product where "name like 'Tightvnc%%'" call uninstall`, followed by WMIC.exe (PID 42516) execution. Security event 4688 captures the full command line showing the WMI query targeting TightVNC software for uninstall.

Sysmon provides comprehensive process creation events (EID 1) for the execution chain: powershell.exe → cmd.exe → WMIC.exe, with detailed parent-child relationships. The WmiPrvSE.exe process (PID 42476) appears in Sysmon EID 1, indicating WMI provider host activation to handle the WMI operations. Process access events (Sysmon EID 10) show PowerShell accessing both cmd.exe and whoami.exe with full access rights (0x1FFFFF), indicating the test framework monitoring spawned processes.

Image load events (Sysmon EID 7) reveal WMIC.exe loading amsi.dll and various Windows Defender components (MpOAV.dll), demonstrating active endpoint protection inspection. Application events show multiple Windows Installer reconfigurations for Python components and other software, suggesting the WMI query triggered broader system inventory operations even though the target TightVNC application wasn't found.

## What This Dataset Does Not Contain

This dataset lacks WMI-specific event logs from the Microsoft-Windows-WMI-Activity channel, which would show the actual WQL query execution, provider interactions, and method call details. The absence of these logs limits visibility into the WMI operation's internal mechanics and success/failure status.

Notably missing are network connection events from Sysmon EID 3, despite the WMIC command targeting "127.0.0.1" — this suggests the WMI operation used local communication mechanisms rather than network protocols. The dataset also lacks registry modification events that typically accompany software uninstallation operations, indicating the target application (TightVNC) was not present on the system.

The PowerShell logs contain only execution policy bypass commands and test framework boilerplate rather than the actual WMI operation details, limiting insight into how the technique was orchestrated from the PowerShell layer.

## Assessment

This dataset provides excellent coverage of WMI execution from a process creation and behavioral perspective, making it highly valuable for detection engineering focused on process-based indicators. The combination of Security 4688 events with complete command lines and Sysmon process creation events offers strong foundations for detecting WMI-based execution patterns.

However, the dataset's utility is somewhat limited by the absence of WMI-specific event sources and the fact that the target application wasn't present, preventing observation of actual software modification behaviors. The rich process telemetry and endpoint protection interactions still make this dataset valuable for understanding WMI execution patterns and building behavioral detections around WMIC.exe usage.

## Detection Opportunities Present in This Data

1. Command line detection for WMIC.exe execution with product queries and method calls, specifically looking for `wmic.*product.*where.*call` patterns in Security 4688 and Sysmon 1 events

2. Parent-child process relationships showing PowerShell or cmd.exe spawning WMIC.exe, indicating potential scripted WMI operations

3. WmiPrvSE.exe process creation events (Sysmon EID 1) as indicators of WMI provider activation, especially when correlated with suspicious parent processes

4. WMIC.exe loading AMSI and Windows Defender components (Sysmon EID 7), indicating endpoint protection inspection of WMI operations

5. Process access patterns where PowerShell accesses cmd.exe and other child processes with full rights (0x1FFFFF), suggesting automated process management

6. File creation events in PowerShell profile directories concurrent with WMI operations, indicating PowerShell-orchestrated WMI execution

7. Privilege escalation indicators in Security 4703 events showing WMIC.exe enabling multiple system privileges required for software management

8. Network-targeted WMIC operations using loopback addresses or remote nodes, detectable through command line analysis of /node parameters
