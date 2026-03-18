# T1059.001-12: PowerShell — PowerShell Session Creation and Use

## Technique Context

T1059.001 (Command and Scripting Interpreter: PowerShell) represents one of the most common execution techniques in Windows environments. PowerShell remoting, specifically through `New-PSSession`, is a legitimate administrative capability that attackers frequently abuse for lateral movement and persistence. This technique allows execution of commands on remote systems using WinRM (Windows Remote Management) over HTTP/HTTPS. Detection engineers focus on identifying suspicious PowerShell session creation patterns, unusual network connections to port 5985/5986, and PowerShell execution with high privileges or in unexpected contexts.

## What This Dataset Contains

This dataset captures a PowerShell remoting attempt that ultimately fails due to access restrictions. The Security channel shows PowerShell process creation (EID 4688) with the full command line: `"powershell.exe" & {New-PSSession -ComputerName $env:COMPUTERNAME; Test-Connection $env:COMPUTERNAME; Set-Content -Path $env:TEMP\T1086_PowerShell_Session_Creation_and_Use -Value "T1086 PowerShell Session Creation and Use"; Get-Content -Path $env:TEMP\T1086_PowerShell_Session_Creation_and_Use; Remove-Item -Force $env:TEMP\T1086_PowerShell_Session_Creation_and_Use}`.

The PowerShell channel provides detailed telemetry including script block creation (EID 4104) showing the actual PowerShell commands, module invocation logging (EID 4103) capturing cmdlet execution with parameters, and WinRM-specific events (EID 8193-8197, 32784) documenting the failed session creation attempt. Key PowerShell events include `New-PSSession -ComputerName ACME-WS02` failing with "Access is denied" (EID 32784), successful execution of `Test-Connection`, `Set-Content`, `Get-Content`, and `Remove-Item` cmdlets.

Sysmon captures process creation for both the parent PowerShell session and child PowerShell process (EID 1), DNS queries for "ACME-WS02" resolution (EID 22), network connections to WinRM port 5985 over IPv6 (EID 3), file creation for the temporary test file (EID 11), and extensive DLL loading events (EID 7) showing PowerShell runtime initialization.

## What This Dataset Does Not Contain

The dataset lacks successful PowerShell remoting telemetry since the `New-PSSession` attempt fails with "Access is denied." This means we don't see successful WinRM authentication, remote PowerShell session establishment, or remote command execution evidence that would occur in a successful attack. The failure appears to be due to insufficient privileges or WinRM configuration restrictions, not Windows Defender blocking.

The Sysmon ProcessCreate events are limited due to the include-mode filtering configuration, so some expected child processes may not appear. Additionally, the PowerShell channel contains significant amounts of framework boilerplate (Set-StrictMode, error handling scriptblocks) that, while legitimate, creates noise around the core attack technique evidence.

## Assessment

This dataset provides excellent visibility into PowerShell remoting attempt patterns, even when unsuccessful. The combination of Security 4688 command-line logging, comprehensive PowerShell operational logging, and Sysmon network/process telemetry creates multiple detection opportunities. The failed authentication provides realistic telemetry that defenders would see when attackers attempt lateral movement without proper credentials or permissions. However, the dataset would be stronger with successful remoting examples to show the complete attack chain and remote execution evidence.

## Detection Opportunities Present in This Data

1. **PowerShell Remoting Cmdlet Detection** - EID 4103 CommandInvocation events for `New-PSSession` with ComputerName parameters, indicating remote PowerShell session attempts
2. **WinRM Network Activity** - Sysmon EID 3 network connections to port 5985 from PowerShell processes, especially to localhost or suspicious targets
3. **PowerShell Script Block Analysis** - EID 4104 script blocks containing `New-PSSession`, `Enter-PSSession`, or other remoting cmdlets
4. **WinRM Error Patterns** - PowerShell EID 32784 errors with "Access is denied" or similar authentication failures indicating failed lateral movement attempts
5. **PowerShell Process Chains** - Security EID 4688 showing PowerShell spawning additional PowerShell processes with remoting command lines
6. **DNS Resolution for Targets** - Sysmon EID 22 DNS queries from PowerShell processes resolving potential lateral movement targets
7. **Privilege Escalation Context** - Security EID 4703 token right adjustments in PowerShell processes attempting remoting
8. **File System Artifacts** - Sysmon EID 11 file creation events for temporary files used in PowerShell remoting scripts
9. **PowerShell Module Loading** - EID 4103 showing System.Management.Automation cmdlets being invoked for remoting operations
10. **Authentication Attempt Correlation** - Security EID 4648 explicit credential usage events correlating with PowerShell remoting attempts
