# T1083-6: File and Directory Discovery — Launch DirLister Executable

## Technique Context

T1083 File and Directory Discovery is a core discovery technique where adversaries enumerate files and directories to understand the target environment, locate sensitive data, or identify tools and configurations that could aid in further compromise. This technique spans from simple directory listing commands to sophisticated file search utilities that can recursively scan entire file systems.

The detection community typically focuses on monitoring execution of native Windows utilities (dir, tree, forfiles), PowerShell cmdlets (Get-ChildItem, Get-Location), and third-party directory enumeration tools. This particular test simulates the execution of a custom directory listing executable called "DirLister.exe" - representing how adversaries might deploy specialized reconnaissance tools rather than relying on built-in utilities that generate more obvious telemetry.

## What This Dataset Contains

This dataset captures a PowerShell-based test that attempts to launch the DirLister.exe utility but fails because the executable is missing. The key events include:

**Process Creation**: Security event 4688 shows PowerShell spawning with command line `"powershell.exe" & {Start-Process \"C:\AtomicRedTeam\atomics\..\ExternalPayloads\DirLister.exe\" Start-Sleep -Second 4 Stop-Process -Name \"DirLister\"}`, clearly revealing the intended execution of the DirLister tool.

**PowerShell Script Block Logging**: Event 4104 captures the exact script content: `& {Start-Process "C:\AtomicRedTeam\atomics\..\ExternalPayloads\DirLister.exe" Start-Sleep -Second 4 Stop-Process -Name "DirLister"}` and the subsequent error handling when the file cannot be found.

**PowerShell Error**: Event 4100 records the failure: `Error Message = This command cannot be run due to the error: The system cannot find the file specified. Fully Qualified Error ID = InvalidOperationException,Microsoft.PowerShell.Commands.StartProcessCommand`.

**Sysmon Process Telemetry**: Event 1 captures the child PowerShell process (PID 30140) with the full command line attempting to execute the DirLister tool, tagged with RuleName `technique_id=T1083,technique_name=File and Directory Discovery`.

**Process Access**: Sysmon event 10 shows process injection-style access patterns as PowerShell manages child process creation, though this is legitimate .NET process spawning behavior.

## What This Dataset Does Not Contain

The dataset lacks the actual execution of DirLister.exe because the file doesn't exist in the ExternalPayloads directory. This means there's no file system enumeration activity, no directory traversal events, and no file access patterns that would normally characterize successful T1083 execution. The test also doesn't trigger Defender blocking behavior since the malicious executable never executes - the failure occurs at the file system level before any security scanning.

Notably absent are Sysmon ProcessCreate events for the DirLister.exe itself, which would normally be captured given the sysmon-modular configuration includes T1083-related process monitoring. The test becomes more about PowerShell error handling and failed process spawning than actual discovery activity.

## Assessment

While this dataset doesn't demonstrate successful T1083 execution, it provides excellent visibility into attempted directory discovery tool deployment. The combination of Security 4688 process creation with full command lines, PowerShell script block logging, and Sysmon process telemetry creates multiple detection opportunities for this attack pattern.

The failure mode actually enhances the dataset's value for detection engineering, showing how PowerShell-based deployment of custom reconnaissance tools generates telemetry even when the tools themselves are missing or blocked. This represents a common real-world scenario where defenders can catch attempted tool deployment before the tools execute.

The PowerShell error logging is particularly valuable, as it captures the specific tool path and intended execution method, providing clear indicators of adversary intent even in failure cases.

## Detection Opportunities Present in This Data

1. **PowerShell Start-Process for External Tools**: Monitor PowerShell script blocks containing Start-Process commands targeting non-standard executables, especially in temporary or payload directories.

2. **Atomic Red Team Path Indicators**: Detect references to "AtomicRedTeam" and "ExternalPayloads" paths in command lines as indicators of security testing or potential adversary tool staging.

3. **Directory Listing Tool Execution**: Alert on execution of non-standard directory enumeration tools like "DirLister.exe" through process creation events.

4. **PowerShell Process Spawning with Discovery Intent**: Correlate PowerShell processes spawning child processes with discovery-related tool names or command patterns.

5. **Failed Tool Execution Patterns**: Monitor PowerShell error events for "system cannot find the file specified" combined with suspicious executable names or paths.

6. **Process Creation Chain Analysis**: Detect PowerShell → PowerShell → intended discovery tool process trees as potential staged discovery operations.

7. **Script Block Content Analysis**: Parse PowerShell script blocks for Start-Process, Stop-Process, and Sleep combinations that indicate automated tool deployment patterns.
