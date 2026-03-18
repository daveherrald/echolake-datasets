# T1219-11: Remote Access Tools — MSP360 Connect Execution

## Technique Context

T1219 Remote Access Tools covers adversaries' use of legitimate remote access and remote administration tools to maintain persistence and execute commands on compromised systems. MSP360 Connect (formerly CloudBerry Remote Assistant) is a legitimate remote access tool used by MSPs and IT administrators for remote support. While legitimate, these tools are frequently abused by threat actors because they provide authenticated remote access, often bypass network security controls, and appear benign to security tools. The detection community focuses on monitoring for unexpected installations of remote access tools, unusual process execution patterns, and network connections to remote access service providers.

## What This Dataset Contains

This dataset captures a failed attempt to execute MSP360 Connect. The key evidence includes:

**PowerShell Execution**: Security event 4688 shows PowerShell being spawned with command line `"powershell.exe" & {Start-Process $env:ProgramFiles\Connect\Connect.exe}`, attempting to launch the MSP360 Connect executable from the standard installation path `C:\Program Files\Connect\Connect.exe`.

**PowerShell Script Block Logging**: Event 4104 captures the actual PowerShell commands: `& {Start-Process $env:ProgramFiles\Connect\Connect.exe}` and `{Start-Process $env:ProgramFiles\Connect\Connect.exe}`, showing the attempt to start the Connect.exe process.

**Execution Failure**: PowerShell event 4100 records the failure: "This command cannot be run due to the error: The system cannot find the file specified" with error ID `InvalidOperationException,Microsoft.PowerShell.Commands.StartProcessCommand`, indicating MSP360 Connect is not installed on the system.

**Process Telemetry**: Sysmon captures the PowerShell process creation (EID 1) with the suspicious command line, process access events (EID 10) showing PowerShell accessing spawned processes, and various DLL load events (EID 7) as PowerShell initializes the .NET runtime.

**System Discovery Activity**: The dataset includes execution of `whoami.exe` (Sysmon EID 1, Security EID 4688), which may be related to the test framework but demonstrates system owner/user discovery techniques commonly used alongside remote access tool deployment.

## What This Dataset Does Not Contain

The dataset lacks evidence of successful MSP360 Connect execution because the software is not installed on the test system. We don't see network connections to MSP360 servers, GUI application startup, or the typical remote access session artifacts. There are no file creation events for MSP360 Connect binaries or configuration files, no registry modifications for persistence, and no service installation events. The technique essentially fails at the first step due to the missing executable.

## Assessment

This dataset provides limited value for detecting successful MSP360 Connect usage but offers excellent visibility into detection opportunities for attempted remote access tool execution. The PowerShell script block logging captures the exact commands used, while Security audit logs provide process creation with command-line details. The failure scenario actually makes the detection more straightforward since the suspicious PowerShell command line attempting to launch Connect.exe is the primary indicator. For building detections around remote access tool abuse, this represents the reconnaissance or initial deployment phase that defenders should monitor.

## Detection Opportunities Present in This Data

1. **Remote Access Tool Process Execution Attempts**: Monitor Security 4688 and Sysmon 1 events for processes attempting to launch known remote access tools like `Connect.exe`, `TeamViewer.exe`, `AnyDesk.exe` from their standard installation paths.

2. **PowerShell Remote Access Tool Invocation**: Alert on PowerShell script blocks (4104) or command lines (4688) containing `Start-Process` combined with remote access tool executable names or installation paths like `$env:ProgramFiles\Connect\`.

3. **Failed Remote Access Tool Execution**: Monitor PowerShell error events (4100) with error IDs like `InvalidOperationException,Microsoft.PowerShell.Commands.StartProcessCommand` when attempting to start processes from common remote access tool installation directories.

4. **Suspicious PowerShell Command Patterns**: Create detection rules for PowerShell processes with command lines containing environment variable expansion (`$env:ProgramFiles`) combined with known remote access tool directory structures.

5. **Process Access Patterns**: Correlate Sysmon 10 events showing PowerShell accessing newly spawned processes with attempts to launch remote access tools, which may indicate injection or monitoring techniques.

6. **System Discovery Following Remote Access Attempts**: Monitor for `whoami.exe` execution (Sysmon 1, Security 4688) in temporal proximity to remote access tool execution attempts, as adversaries often perform reconnaissance after establishing remote access.
