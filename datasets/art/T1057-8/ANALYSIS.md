# T1057-8: Process Discovery — Process Discovery - PC Hunter

## Technique Context

Process Discovery (T1057) enables adversaries to enumerate running processes on a system to understand the current state, identify security tools, find potential targets for injection, or gather information about system activity. This technique is fundamental to situational awareness during post-exploitation phases and is used by virtually all attackers to understand their environment.

PC Hunter is a legitimate system analysis tool commonly used by security researchers and system administrators for deep system inspection, including process enumeration with detailed information about running processes, loaded modules, and system components. However, its powerful capabilities also make it attractive to adversaries for reconnaissance activities. The detection community focuses on identifying unusual process enumeration activities, especially when performed by non-standard tools or in conjunction with other suspicious behaviors.

## What This Dataset Contains

This dataset captures an attempted execution of PC Hunter that fails due to a missing file. The security logs show the PowerShell command line that attempts to launch the tool:

Security 4688 events show the process creation chain starting with `powershell.exe` executing the command `"powershell.exe" & {Start-Process -FilePath \"C:\Temp\ExternalPayloads\PCHunter_free\PChunter64.exe\"}`. A single Sysmon 1 (ProcessCreate) event captures whoami.exe execution with command line `"C:\Windows\system32\whoami.exe"`, indicating some basic system reconnaissance occurred.

PowerShell events in the Microsoft-Windows-PowerShell/Operational channel document the attempted execution with EID 4104 script blocks showing `& {Start-Process -FilePath "C:\Temp\ExternalPayloads\PCHunter_free\PChunter64.exe"}` and the associated Start-Process cmdlet invocation. Critically, EID 4100 and 4103 events capture the execution failure: "This command cannot be run due to the error: The system cannot find the file specified" with the TerminatingError showing the Start-Process cmdlet could not locate the PCHunter64.exe binary.

Sysmon events include standard PowerShell initialization artifacts (EID 7 image loads for .NET runtime components, EID 17 named pipe creation, EID 11 PowerShell profile file access) and one notable EID 10 ProcessAccess event showing PowerShell accessing the whoami.exe process with GrantedAccess 0x1FFFFF.

## What This Dataset Does Not Contain

The dataset lacks the actual PC Hunter execution since the binary was not present at the expected path `C:\Temp\ExternalPayloads\PCHunter_free\PChunter64.exe`. Therefore, there are no events showing the characteristic process enumeration activities that PC Hunter would normally perform, such as extensive process access events, registry queries, or the creation of PC Hunter's own processes.

No Sysmon ProcessCreate events capture the attempted PC Hunter execution because the file system error occurred before the process could be created. The sysmon-modular configuration would likely have captured PC Hunter as a potentially suspicious binary if it had been present and executed.

There are no network connections, file modifications, or other artifacts that would result from successful PC Hunter execution and its subsequent process discovery activities.

## Assessment

This dataset provides moderate value for detection engineering focused on identifying attempted use of system analysis tools, even when execution fails. The PowerShell telemetry clearly shows the intent to execute PC Hunter through the Start-Process cmdlet with the specific file path. The execution failure actually makes the attempt more observable since the error conditions generate distinctive PowerShell error events.

The combination of Security 4688 process creation events with full command-line logging and PowerShell operational logs provides solid coverage for detecting this type of tool deployment attempt. However, the dataset's utility is limited for understanding PC Hunter's actual process discovery behavior since the tool never executed successfully.

## Detection Opportunities Present in This Data

1. **Tool deployment attempts via PowerShell Start-Process** - Monitor PowerShell EID 4103/4104 events for Start-Process cmdlet invocations targeting known system analysis tools like PC Hunter in suspicious directories

2. **Security tool execution attempts in temp directories** - Alert on Security 4688 events showing processes attempting to execute binaries from `\Temp\ExternalPayloads\` or similar staging directories

3. **PowerShell execution failures for system tools** - Track PowerShell EID 4100 error events containing "system cannot find the file specified" when attempting to launch known reconnaissance tools

4. **Process access patterns during tool deployment** - Correlate Sysmon EID 10 ProcessAccess events from PowerShell with high privileges (0x1FFFFF) against system utilities like whoami.exe

5. **Command-line indicators of PC Hunter usage** - Create signatures for command lines containing "PChunter64.exe" or "PCHunter" regardless of execution success

6. **PowerShell script block analysis for tool invocation** - Monitor EID 4104 script blocks for patterns like `Start-Process -FilePath` followed by paths to known system analysis tools
