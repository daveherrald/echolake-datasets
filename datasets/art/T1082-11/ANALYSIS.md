# T1082-11: System Information Discovery — Environment variables discovery on windows

## Technique Context

T1082 System Information Discovery is a fundamental Discovery tactic technique where adversaries gather information about the compromised system's configuration, hardware, software, and environment. Environment variable enumeration specifically reveals system paths, user contexts, installed software locations, and configuration details that attackers use for situational awareness and privilege escalation planning. Defenders typically focus on detecting unusual process execution patterns, command-line arguments that query system information, and PowerShell cmdlets or built-in Windows utilities being used for reconnaissance.

Common attack vectors include using `whoami`, `set`, `Get-ChildItem Env:`, `systeminfo`, and similar commands. The technique often appears early in attack chains as adversaries orient themselves within the compromised environment.

## What This Dataset Contains

This dataset captures a straightforward environment variable discovery test with two distinct approaches executed from PowerShell. The Security channel shows the core process execution evidence:

- PowerShell process (PID 7052) spawning `whoami.exe` with command line `"C:\Windows\system32\whoami.exe"`
- PowerShell spawning `cmd.exe` with command line `"cmd.exe" /c set` to enumerate environment variables
- Both child processes completing successfully with exit status 0x0

The Sysmon data provides additional process context with EID 1 events showing the same executions but with more detailed metadata including process GUIDs, parent-child relationships, and file hashes. Notably, Sysmon EID 10 (Process Access) events show PowerShell accessing both the whoami.exe and cmd.exe processes with full access rights (0x1FFFFF), which is expected behavior for parent processes monitoring their children.

PowerShell script block logging (EID 4104) contains only test framework boilerplate (`Set-StrictMode` and error handling scriptblocks) rather than the actual discovery commands, indicating the test used direct PowerShell cmdlets or started external processes rather than PowerShell scripts.

## What This Dataset Does Not Contain

The dataset lacks direct PowerShell environment variable enumeration commands like `Get-ChildItem Env:` or `$env:` usage in the PowerShell script blocks. The actual environment variable output from the `set` command is not captured in these event logs. There's no evidence of more sophisticated discovery techniques like WMI queries (`Get-WmiObject Win32_Environment`) or registry enumeration that adversaries might use for comprehensive environment discovery.

The test appears to focus on the basic command-line approach rather than PowerShell-native discovery methods, which would generate different telemetry patterns.

## Assessment

This dataset provides solid telemetry for detecting basic environment discovery activities. The Security 4688 events with command-line logging capture the essential detection artifacts, while Sysmon adds valuable process relationship context and file integrity data. The combination of `whoami` and `cmd /c set` represents common discovery patterns that detection rules can reliably identify.

However, the dataset's utility is somewhat limited by its focus on command-line utilities rather than PowerShell-native discovery methods. Modern attackers increasingly use PowerShell cmdlets that might not trigger the same process creation events, making this dataset more representative of traditional or less sophisticated discovery approaches.

## Detection Opportunities Present in This Data

1. **Command-line pattern detection** - Security 4688 events showing `cmd.exe` with `/c set` parameter indicate environment variable enumeration attempts

2. **System utility process creation** - Sysmon EID 1 and Security 4688 events capturing `whoami.exe` execution, especially when spawned by scripting engines like PowerShell

3. **PowerShell child process monitoring** - Process creation events where `powershell.exe` spawns system information utilities (whoami, cmd, systeminfo, etc.)

4. **Process access patterns** - Sysmon EID 10 events showing PowerShell accessing system utilities with full privileges may indicate automated discovery scripting

5. **Discovery command clustering** - Multiple system information commands executed in rapid succession by the same parent process suggest reconnaissance activity

6. **Execution context analysis** - Commands executed under SYSTEM context from PowerShell may indicate post-exploitation discovery rather than legitimate administration
