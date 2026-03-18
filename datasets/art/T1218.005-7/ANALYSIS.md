# T1218.005-7: Mshta — Invoke HTML Application - JScript Engine with Rundll32 and Inline Protocol Handler

## Technique Context

T1218.005 (Mshta) is a defense evasion technique where attackers abuse Microsoft's HTML Application Host (mshta.exe) to execute malicious code while bypassing application controls. Mshta.exe is a legitimate Windows utility designed to execute .hta files containing HTML and scripting code. Attackers leverage this signed binary to proxy execution of JavaScript, VBScript, or other scripting languages, often fetching payloads from remote sources or using inline protocol handlers.

This specific test variant uses rundll32.exe to invoke mshta functionality with JScript engine and an "About" inline protocol handler. The detection community focuses on unusual mshta.exe process creation patterns, command-line arguments containing script content or suspicious URLs, network connections from mshta processes, and child process spawning from mshta execution.

## What This Dataset Contains

This dataset captures a PowerShell-orchestrated execution of the Atomic Red Team test but notably **does not contain the expected mshta.exe or rundll32.exe process creation events**. The primary telemetry shows:

**PowerShell Execution Chain:**
- Security 4688 shows PowerShell process creation: `"powershell.exe" & {Invoke-ATHHTMLApplication -ScriptEngine JScript -InlineProtocolHandler About -UseRundll32 -Rundll32FilePath $env:windir\system32\rundll32.exe}`
- PowerShell 4104 script block contains the test command: `& {Invoke-ATHHTMLApplication -ScriptEngine JScript -InlineProtocolHandler About -UseRundll32 -Rundll32FilePath $env:windir\system32\rundll32.exe}`

**Supporting Process Activity:**
- Sysmon 1 events capture whoami.exe execution (PID 36012) and a secondary PowerShell process (PID 12464) 
- Multiple Sysmon 7 events show .NET Framework and Windows Defender DLL loading in PowerShell processes
- Sysmon 10 process access events show PowerShell accessing both whoami.exe and the secondary PowerShell process with full access (0x1FFFFF)
- Sysmon 17 pipe creation events for PowerShell host communication

**What's Missing - The Core Technique:**
No mshta.exe or rundll32.exe process creation events appear in Sysmon or Security logs, indicating the technique execution was likely blocked or failed before reaching the target binaries.

## What This Dataset Does Not Contain

This dataset is missing the fundamental telemetry expected from successful T1218.005 execution:

- **No mshta.exe process creation** - Neither Sysmon 1 nor Security 4688 show mshta.exe launching
- **No rundll32.exe process creation** - The test specifies using rundll32 to invoke mshta functionality, but no rundll32 execution is captured
- **No network connections** - Sysmon network events would typically show mshta making HTTP requests for remote payloads
- **No file system artifacts** - Missing temporary .hta files or downloaded payloads that mshta would normally process

The absence of these events suggests either Windows Defender blocked the execution before mshta/rundll32 launched, the PowerShell function failed to properly invoke the binaries, or the test executed so quickly that the processes weren't captured. The PowerShell script block logging confirms the command was parsed but doesn't guarantee successful binary execution.

## Assessment

This dataset provides limited utility for building detections specifically for T1218.005 (Mshta) since it lacks the core technique execution telemetry. However, it offers value for detecting the **preparatory phases** of mshta attacks - specifically PowerShell-based delivery mechanisms and suspicious script block content.

The data sources captured here (Security 4688, PowerShell 4104, Sysmon process monitoring) are excellent for building detections, but this particular execution appears to have been incomplete or blocked. For comprehensive T1218.005 detection development, you would need datasets showing successful mshta.exe process creation with suspicious command-lines, network activity, and file operations.

The telemetry quality is high with full command-line logging and PowerShell script block capture, making it valuable for upstream detection of attack preparation even when the final payload delivery fails.

## Detection Opportunities Present in This Data

1. **PowerShell command-line detection** - Monitor Security 4688 events for PowerShell processes with command-lines containing "Invoke-ATHHTMLApplication", "mshta", or "rundll32" parameters indicating mshta abuse preparation

2. **PowerShell script block analysis** - Alert on PowerShell 4104 events containing functions like "Invoke-ATHHTMLApplication" combined with parameters like "-ScriptEngine JScript" and "-UseRundll32"

3. **Suspicious PowerShell process access patterns** - Monitor Sysmon 10 events where PowerShell processes access other processes with full permissions (0x1FFFFF), which may indicate process manipulation attempts

4. **PowerShell child process monitoring** - Track Sysmon 1 events where PowerShell spawns unexpected child processes, particularly system utilities that could be used for defense evasion

5. **Failed execution detection** - Build detections for PowerShell scripts that attempt to invoke mshta/rundll32 but fail to generate expected child processes, indicating potential security control effectiveness or attack failure
