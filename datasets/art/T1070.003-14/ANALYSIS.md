# T1070.003-14: Clear Command History — Clear PowerShell Session History

## Technique Context

T1070.003 Clear Command History is a defense evasion technique where attackers remove evidence of their activities by clearing shell command histories. In PowerShell environments, this commonly involves using the `Clear-History` cmdlet to remove the current session's command history from memory, or manipulating PowerShell history files to delete persistent command records. While this technique doesn't prevent logging by centralized security systems, it can hamper local forensics and investigations that rely on command history artifacts. The detection community focuses on monitoring for history clearing commands, unusual PowerShell cmdlet usage patterns, and file system modifications to PowerShell history files.

## What This Dataset Contains

This dataset captures a straightforward execution of PowerShell's `Clear-History` cmdlet. The key telemetry includes:

**Command Execution Evidence:**
- Security 4688 showing PowerShell process creation with command line `"powershell.exe" & {Clear-History}`
- PowerShell 4104 script block logging capturing the actual command: `& {Clear-History}` and `{Clear-History}`
- PowerShell 4103 module logging showing `CommandInvocation(Clear-History): "Clear-History"` with full context including Host Application, Runspace ID, and Pipeline ID

**Process Chain:**
The technique execution follows a clear process hierarchy with parent PowerShell (PID 26988) spawning child PowerShell (PID 24988) specifically to execute the Clear-History command.

**Supporting Context:**
- Multiple Sysmon EID 1 process creation events for PowerShell instances involved
- Extensive Sysmon EID 7 image load events showing .NET runtime and PowerShell automation libraries being loaded
- Sysmon EID 17 named pipe creation events for PowerShell hosts
- A tangential `whoami.exe` execution (likely test framework verification)

## What This Dataset Does Not Contain

This dataset captures only the in-memory session history clearing via `Clear-History` cmdlet. It does not contain:

**File-based History Clearing:**
- No evidence of PSReadLine history file manipulation (`ConsoleHost_history.txt` modifications)
- No file deletion events targeting PowerShell history files
- No registry modifications to PowerShell history settings

**Broader Anti-Forensics Activity:**
- The technique execution is isolated and doesn't show typical operational context where history clearing might occur after suspicious commands
- No evidence of other log tampering or anti-forensics techniques

**Cross-Platform Variations:**
- Only Windows PowerShell 5.1 clearing, not PowerShell Core or other shell environments

## Assessment

This dataset provides excellent telemetry for detecting the `Clear-History` cmdlet execution through multiple complementary log sources. The PowerShell operational logs (4103/4104) provide the most direct evidence, while Security 4688 events offer command-line visibility even if PowerShell logging were disabled. The combination of process creation, script block logging, and module logging creates multiple detection opportunities that would be difficult for an attacker to evade simultaneously. However, the dataset only covers the cmdlet-based approach and doesn't demonstrate file-based history tampering, which is equally important for comprehensive detection coverage.

## Detection Opportunities Present in This Data

1. **PowerShell Script Block Detection** - Monitor PowerShell EID 4104 for script blocks containing `Clear-History` cmdlet execution

2. **PowerShell Module Logging** - Alert on PowerShell EID 4103 CommandInvocation events where Command Name equals "Clear-History"

3. **Command Line Analysis** - Detect Security EID 4688 process creation events with command lines containing "Clear-History" or variations with PowerShell execution

4. **PowerShell Process Spawning** - Monitor for PowerShell processes launched specifically to execute single commands containing history clearing functions

5. **Execution Context Analysis** - Flag PowerShell executions with suspicious Host Application patterns or short-lived processes that only execute history clearing commands

6. **Process Chain Correlation** - Identify parent-child PowerShell relationships where child processes are created solely for anti-forensics activities

7. **PowerShell Engine Loading** - Correlate Sysmon EID 7 System.Management.Automation.dll loads with subsequent Clear-History command execution for behavioral analysis
