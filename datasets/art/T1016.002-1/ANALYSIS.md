# T1016.002-1: Wi-Fi Discovery — Enumerate Stored Wi-Fi Profiles And Passwords via netsh

## Technique Context

T1016.002 Wi-Fi Discovery is a sub-technique of System Network Configuration Discovery focused on enumerating stored wireless network profiles and credentials. Adversaries commonly use this technique during post-compromise reconnaissance to discover available Wi-Fi networks, previously connected SSIDs, and potentially stored passwords in clear text. The `netsh wlan show profile * key=clear` command is the canonical Windows method for this discovery, as it reveals all stored wireless profiles with their associated passwords when available. This technique is frequently observed in credential harvesting operations and lateral movement preparation, particularly on laptops and mobile devices that have connected to multiple networks. Detection engineering typically focuses on monitoring netsh.exe execution with WLAN-related parameters, as legitimate administrative use of these specific commands is relatively uncommon.

## What This Dataset Contains

The dataset captures a complete execution chain showing PowerShell invoking the classic Wi-Fi discovery command. The process chain begins with PowerShell (PID 7272) executing `cmd.exe /c netsh wlan show profile * key=clear`, followed by cmd.exe (PID 7772) spawning netsh.exe (PID 8144) with the command line `netsh wlan show profile * key=clear`. Security event 4688 captures both the cmd.exe creation with the full command `"cmd.exe" /c netsh wlan show profile * key=clear` and the netsh.exe creation with `netsh wlan show profile * key=clear`. Sysmon EID 1 events provide additional process details, including file hashes and parent-child relationships. Both processes exit with status 0x1, indicating they executed but found no wireless profiles (expected on a desktop workstation). The technique execution is preceded by a `whoami.exe` execution, showing typical reconnaissance behavior. PowerShell events show only standard test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) without the actual technique commands.

## What This Dataset Does Not Contain

The dataset lacks the actual output from the netsh command, as this technique focuses on information gathering rather than creating persistent artifacts. There are no network-related Sysmon events (EID 3) because netsh is querying local configuration rather than making network connections. Registry access events are not captured, though netsh would typically read wireless profile data from the registry. The PowerShell script block logging (EID 4104) contains only framework boilerplate and doesn't capture the actual technique execution commands, likely because the test executed the commands through a different mechanism. File creation events show only PowerShell profile updates, not technique-related artifacts. Windows Defender did not block this technique, as netsh.exe is a legitimate Windows utility and the command execution completed successfully.

## Assessment

This dataset provides excellent process execution telemetry for detecting Wi-Fi discovery techniques. The Security 4688 events with command-line logging are particularly valuable, capturing both the cmd.exe wrapper and the actual netsh.exe execution with full parameters. Sysmon EID 1 events add crucial process relationship context, showing the PowerShell → cmd.exe → netsh.exe execution chain. The combination of process creation events, command lines, and parent-child relationships gives detection engineers multiple opportunities to identify this behavior. However, the dataset would be stronger with registry access events showing netsh reading wireless profile data, and PowerShell script block events capturing the actual technique commands. The exit codes (0x1) provide useful context that no wireless profiles were found, which could be incorporated into detection logic to reduce false positives.

## Detection Opportunities Present in This Data

1. **Netsh WLAN Profile Enumeration**: Monitor Security EID 4688 or Sysmon EID 1 for netsh.exe with command lines containing "wlan show profile" and "key=clear" parameters, especially when executed by non-administrative users or in automated contexts.

2. **Command Shell WLAN Discovery Chain**: Detect cmd.exe processes with command lines containing "netsh wlan show profile * key=clear", particularly when spawned by scripting engines like PowerShell, indicating automated credential harvesting attempts.

3. **Process Relationship Analysis**: Correlate PowerShell or other scripting processes spawning cmd.exe which then executes netsh.exe with WLAN parameters, as this execution pattern is uncommon in legitimate administrative workflows.

4. **Netsh Security Software Discovery**: Monitor Sysmon EID 1 process creations for netsh.exe classified under the Security Software Discovery rule (as tagged in this dataset), indicating potential reconnaissance activity.

5. **Reconnaissance Behavior Clustering**: Combine netsh WLAN discovery with other reconnaissance tools like whoami.exe (as shown in this dataset) to identify broader system discovery campaigns and prioritize investigation.
