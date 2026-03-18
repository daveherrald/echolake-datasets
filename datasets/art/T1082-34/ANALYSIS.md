# T1082-34: System Information Discovery — System Information Discovery - Windows Operating System Discovery via PowerShell

## Technique Context

T1082 (System Information Discovery) is a fundamental reconnaissance technique where adversaries gather information about the operating system and computer/hardware configurations. This technique is consistently present across attack frameworks and is often among the first activities performed after initial access. Attackers use system information to understand the environment, plan privilege escalation paths, identify defense mechanisms, and determine lateral movement opportunities. The specific test case focuses on operating system discovery via PowerShell's `Get-CimInstance Win32_OperatingSystem` cmdlet, which is a common method for programmatically retrieving OS details including version, architecture, and system paths. Detection engineers focus on monitoring for suspicious system information gathering patterns, especially when performed by unexpected processes or in rapid succession with other reconnaissance activities.

## What This Dataset Contains

The dataset captures a PowerShell-based OS discovery sequence executing `Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, ServicePackMajorVersion, OSArchitecture, CSName, WindowsDirectory | Out-null`. The Security channel shows the complete process chain in 4688 events: an initial PowerShell process (PID 26392) spawning `whoami.exe` (PID 1448), followed by another PowerShell process (PID 44920) with the full command line `"powershell.exe" & {Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, ServicePackMajorVersion, OSArchitecture, CSName, WindowsDirectory | Out-null}`. The PowerShell channel contains 4103 events showing the CIM cmdlet execution with parameter bindings and the actual OS data retrieved: `@{Caption=Microsoft Windows 11 Enterprise Evaluation; Version=10.0.22631; ServicePackMajorVersion=0; OSArchitecture=64-bit; CSName=ACME-WS02; WindowsDirectory=C:\Windows}`. Sysmon provides extensive DLL loading events (EIDs 7) for .NET Framework components and process creation events (EID 1) with rule names matching T1033 (whoami.exe) and T1083 (PowerShell file discovery), plus process access events (EID 10) showing PowerShell accessing spawned processes.

## What This Dataset Does Not Contain

The dataset lacks WMI provider logs that would show the underlying WMI queries executed by Get-CimInstance. While we see the PowerShell cmdlet execution, the actual CIM/WMI subsystem interactions are not captured in the available channels. Additionally, the sysmon-modular configuration's include-mode filtering means many standard processes aren't captured in Sysmon EID 1 events - we only see PowerShell and whoami.exe because they match specific suspicious patterns. The dataset doesn't contain any blocked or failed attempts, as Windows Defender allowed all activities to complete successfully. Network-based system discovery techniques or WMI queries from other tools would not be represented here.

## Assessment

This dataset provides excellent coverage for detecting PowerShell-based OS discovery activities. The combination of Security 4688 events with full command-line logging, PowerShell 4103/4104 script block and module logging, and Sysmon process/DLL monitoring creates multiple detection opportunities. The command line in Security events clearly shows the Get-CimInstance execution, while PowerShell logs capture both the cmdlet invocation and the actual system data retrieved. The presence of both attempted execution telemetry and successful result data makes this particularly valuable for building behavioral detections. However, detection engineers should note that this represents a very straightforward, unobfuscated approach to OS discovery - real-world adversaries may use more subtle or indirect methods.

## Detection Opportunities Present in This Data

1. **PowerShell CIM/WMI OS queries** - Security 4688 events with command lines containing `Get-CimInstance Win32_OperatingSystem` or similar WMI class queries targeting system information

2. **PowerShell module logging for CIM cmdlets** - PowerShell 4103 events showing `Get-CimInstance` parameter bindings with `ClassName` value of `Win32_OperatingSystem`

3. **System information retrieval in PowerShell script blocks** - PowerShell 4104 events containing `Get-CimInstance Win32_OperatingSystem` with Select-Object operations targeting OS properties

4. **PowerShell process spawning with discovery command lines** - Sysmon EID 1 events where PowerShell processes have command lines containing OS discovery cmdlets combined with output redirection

5. **Sequential discovery process execution** - Correlation of whoami.exe (T1033) followed by PowerShell OS queries (T1082) within short timeframes from the same parent process

6. **CIM cmdlet result capture** - PowerShell 4103 events containing OS information in parameter bindings, particularly Caption, Version, OSArchitecture fields that indicate successful system enumeration

7. **PowerShell process access to discovery tools** - Sysmon EID 10 events showing PowerShell processes accessing whoami.exe or other system tools with high-privilege access rights (0x1FFFFF)

8. **Multiple PowerShell instances for discovery** - Pattern of parent PowerShell processes spawning child PowerShell instances specifically for running discovery commands rather than interactive sessions
