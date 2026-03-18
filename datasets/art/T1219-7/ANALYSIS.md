# T1219-7: Remote Access Tools — RemotePC Software Execution

## Technique Context

T1219 (Remote Access Tools) covers adversaries using legitimate remote access software to maintain persistence and execute commands on compromised systems. These tools blur the line between legitimate administration and malicious activity, making detection challenging. Common remote access tools include TeamViewer, AnyDesk, Chrome Remote Desktop, and in this case, RemotePC.

The detection community focuses on monitoring for unexpected installations of remote access software, unusual network connections to remote access service providers, process execution patterns associated with remote access tools, and behavioral indicators like administrative tool usage during off-hours. Since these tools are often legitimate, detection strategies emphasize context and baseline deviations rather than categorical blocking.

## What This Dataset Contains

This dataset captures an attempt to execute RemotePC.exe that fails because the binary doesn't exist at the expected location. The execution chain shows:

**PowerShell Command Execution:**
- Security EID 4688 shows PowerShell spawning with command line: `"powershell.exe" & {Start-Process \"C:\AtomicRedTeam\atomics\..\ExternalPayloads\RemotePC.exe\"}`
- PowerShell EID 4104 captures the script block: `& {Start-Process "C:\AtomicRedTeam\atomics\..\ExternalPayloads\RemotePC.exe"}`

**Process Creation Chain:**
- Sysmon EID 1 captures the PowerShell process creation (PID 19044) with the Start-Process command
- Parent process is another PowerShell instance (PID 39092)
- Both processes run as NT AUTHORITY\SYSTEM

**Error Handling:**
- PowerShell EID 4100 shows the failure: "Error Message = This command cannot be run due to the error: The system cannot find the file specified."
- The test framework properly captures the failed execution attempt

**Supporting Telemetry:**
- Sysmon EID 7 events show .NET runtime loading in PowerShell processes
- Sysmon EID 10 shows process access events as PowerShell attempts to start the target process
- Sysmon EID 17 captures named pipe creation for PowerShell inter-process communication
- Multiple EID 4689 events document process termination with exit code 0x0

## What This Dataset Does Not Contain

The dataset doesn't contain successful RemotePC execution because the binary file `C:\AtomicRedTeam\atomics\..\ExternalPayloads\RemotePC.exe` doesn't exist on the test system. Consequently, there are no:

- Network connections to RemotePC service infrastructure
- Registry modifications that RemotePC would typically make during installation or execution
- File system artifacts from RemotePC installation
- GUI window events or user interface telemetry
- Actual remote access session establishment

This represents a common scenario where the payload delivery or staging phase fails, but the initial execution attempt is still captured in telemetry. Windows Defender doesn't block the PowerShell execution since it's attempting to run a non-existent file rather than malicious code.

## Assessment

This dataset provides moderate value for detection engineering focused on remote access tool deployment attempts. The PowerShell command line and script block logging clearly capture the intent to execute remote access software, even when the execution fails. The Security and Sysmon process creation events provide good visibility into the execution chain.

The failure scenario is actually valuable because it demonstrates how detection logic should identify suspicious remote access tool deployment attempts regardless of success. However, the dataset would be significantly stronger with a successful execution showing the complete attack lifecycle, network behavior, and persistence mechanisms.

## Detection Opportunities Present in This Data

1. **PowerShell Command Line Analysis** - Security EID 4688 and Sysmon EID 1 contain command lines referencing remote access tools (Start-Process with RemotePC.exe), enabling detection of deployment attempts through process command line monitoring.

2. **PowerShell Script Block Monitoring** - PowerShell EID 4104 captures the exact Start-Process command targeting remote access software, allowing script content analysis for remote tool execution patterns.

3. **Process Tree Analysis** - Sysmon EID 1 events show PowerShell spawning chains attempting to launch remote access tools, enabling detection through parent-child process relationships and execution context analysis.

4. **Failed Execution Detection** - PowerShell EID 4100 error messages can identify failed remote access tool deployment attempts, providing early warning of incomplete attack chains before tools become operational.

5. **File Path Pattern Detection** - Command lines and script blocks reference AtomicRedTeam payload directories and RemotePC.exe specifically, enabling path-based detection rules for remote access tool staging locations.

6. **PowerShell Process Access Monitoring** - Sysmon EID 10 shows PowerShell accessing spawned processes during remote tool launch attempts, providing behavioral indicators of process manipulation during deployment.
