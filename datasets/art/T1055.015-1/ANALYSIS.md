# T1055.015-1: ListPlanting — Process injection ListPlanting

## Technique Context

T1055.015 ListPlanting is a sophisticated process injection technique that exploits Windows' handling of list-view controls to inject code into other processes. The technique works by manipulating list-view controls in target applications, particularly those using common controls like ListView32, to execute arbitrary code within the target process's address space. This technique is especially effective against GUI applications that use Windows common controls.

ListPlanting differs from other injection methods by targeting the visual components of applications rather than core process structures. It leverages the fact that list-view controls can be manipulated to execute code through their window procedure handling mechanisms. The detection community focuses on process access events with specific access rights patterns, unusual inter-process communication, and monitoring for manipulation of GUI application controls.

## What This Dataset Contains

The dataset shows a failed attempt to execute the ListPlanting technique. The PowerShell command line in Security 4688 reveals the test attempted to launch `"C:\AtomicRedTeam\atomics\T1055.015\bin\ListPlanting.exe"`, but this executable was not found on the system. The PowerShell 4100 error confirms this: `"This command cannot be run due to the error: The system cannot find the file specified."` with `Fully Qualified Error ID = InvalidOperationException,Microsoft.PowerShell.Commands.StartProcessCommand`.

The technique implementation involved:
- PowerShell script execution containing `Start-Process "C:\AtomicRedTeam\atomics\T1055.015\bin\ListPlanting.exe"`
- Follow-up commands to sleep 7 seconds and terminate any Notepad processes
- Multiple PowerShell process creations (PIDs 35632, 36944, 38148, 38200)
- Process access events from Sysmon EID 10 showing PowerShell accessing whoami.exe (PID 34664) and another PowerShell process (PID 38148) with full access rights (0x1FFFFF)

The Sysmon process access events show legitimate process interaction rather than injection artifacts, as the ListPlanting executable never successfully launched.

## What This Dataset Does Not Contain

The dataset lacks the core technique execution because the ListPlanting.exe binary was missing from the expected path. Consequently, there are no:
- Actual ListPlanting injection events
- Target process manipulation (Notepad or other GUI applications)
- List-view control manipulation artifacts
- Successful code injection telemetry
- The specific API calls and memory operations characteristic of ListPlanting

The missing binary prevented the technique from demonstrating its primary detection signatures. The Sysmon process access events present are from normal PowerShell operations, not injection attempts. No Sysmon ProcessCreate events for the ListPlanting executable appear because the sysmon-modular config uses include-mode filtering and the process never started.

## Assessment

This dataset has limited utility for detection engineering focused on T1055.015 ListPlanting. The failed execution provides only the PowerShell wrapper telemetry without the actual injection technique. The value lies primarily in demonstrating the reconnaissance and setup phases - PowerShell launching external injection tools and the error handling when tools are missing.

For building ListPlanting detections, this dataset offers insight into the delivery mechanism but lacks the core injection behaviors. The process access patterns shown are normal PowerShell operations rather than injection-specific events. Detection engineers would need datasets with successful ListPlanting executions to develop meaningful rules targeting the technique's unique signatures.

## Detection Opportunities Present in This Data

1. **Failed injection tool execution** - PowerShell 4100 errors mentioning "ListPlanting.exe" or similar injection tool names
2. **Atomic Red Team artifact paths** - Command lines referencing `\AtomicRedTeam\atomics\T1055.015\bin\` directory structures
3. **PowerShell process spawning patterns** - Multiple PowerShell processes spawned in rapid succession for technique testing
4. **Post-injection cleanup commands** - PowerShell scripts containing `Get-Process -Name Notepad | Stop-Process -Force` patterns following injection attempts
5. **Process access enumeration** - Sysmon EID 10 events showing PowerShell accessing other processes with full rights, though these are common and would require additional context for reliable detection
