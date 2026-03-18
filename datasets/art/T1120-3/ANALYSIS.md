# T1120-3: Peripheral Device Discovery — Peripheral Device Discovery via fsutil

## Technique Context

T1120 (Peripheral Device Discovery) involves adversaries enumerating connected storage devices, network shares, and removable media to identify valuable data sources or lateral movement opportunities. The fsutil utility is a legitimate Windows administrative tool commonly abused for this purpose, specifically using `fsutil fsinfo drives` to list all available drive letters and volumes on the system. This technique is frequently observed in post-exploitation phases where attackers survey the environment for data exfiltration targets or additional attack vectors. Detection engineers focus on monitoring process execution patterns and command-line arguments that indicate systematic enumeration activities, particularly when executed from suspicious parent processes or in automated sequences.

## What This Dataset Contains

This dataset captures a clean execution of peripheral device discovery using fsutil. The primary evidence appears in Security event 4688, showing the full process chain: PowerShell (PID 6924) spawning `"cmd.exe" /c fsutil fsinfo drives`, which then creates `fsutil fsinfo drives` (PID 13624). The Sysmon data provides complementary process creation events (EID 1) with detailed hashes and parent-child relationships. Sysmon EID 10 (Process Access) events show PowerShell accessing both cmd.exe and fsutil.exe processes with full access rights (0x1FFFFF), indicating normal process management rather than injection attempts. All processes executed successfully with exit status 0x0, and the technique completed without interference from Windows Defender. The dataset also contains standard PowerShell initialization telemetry, including .NET assembly loads and Windows Defender integration DLL loads, but no actual PowerShell script content related to the technique execution.

## What This Dataset Does Not Contain

The dataset lacks the actual output of the fsutil command - there are no file operations, network connections, or registry modifications that would indicate what drives were discovered or how that information was used. Sysmon ProcessCreate events for cmd.exe are present because the sysmon-modular config includes cmd.exe in its process creation monitoring rules, but many legitimate system processes would not be captured due to the filtered configuration. The PowerShell channel contains only framework initialization script blocks rather than the actual command execution that triggered the fsutil enumeration. There are no network events or file access patterns that would indicate follow-up activities based on the discovery results.

## Assessment

This dataset provides excellent coverage for detecting the core T1120 technique execution. The combination of Security 4688 events with full command-line logging and Sysmon EID 1 process creation events offers robust detection opportunities for fsutil-based peripheral device discovery. The process hierarchy is clearly documented, and the command-line arguments are preserved intact. However, the dataset's detection value is somewhat limited by the absence of output handling or subsequent actions based on the discovery results. For building comprehensive detections, analysts would benefit from additional datasets showing how discovered drive information is typically consumed in real attack scenarios.

## Detection Opportunities Present in This Data

1. **Process creation monitoring for fsutil.exe with fsinfo drives parameters** - Sysmon EID 1 and Security EID 4688 both capture `fsutil fsinfo drives` execution with full command line details and parent process context.

2. **Suspicious parent-child process relationships** - PowerShell spawning cmd.exe which spawns fsutil.exe for drive enumeration can indicate scripted reconnaissance activity, observable through process GUID relationships in Sysmon.

3. **Command-line pattern matching** - The exact command `fsutil fsinfo drives` provides a high-fidelity detection signature, captured in both Security and Sysmon logs with process metadata.

4. **Process access pattern analysis** - Sysmon EID 10 events showing PowerShell accessing spawned reconnaissance processes with full rights (0x1FFFFF) may indicate automated tooling rather than interactive commands.

5. **Execution context correlation** - System-level execution (NT AUTHORITY\SYSTEM) of discovery commands outside typical administrative workflows can indicate compromise, with user context preserved in both log sources.

6. **PowerShell-initiated reconnaissance chains** - The process tree starting from powershell.exe and culminating in discovery tools provides detection opportunities for scripted enumeration campaigns.
