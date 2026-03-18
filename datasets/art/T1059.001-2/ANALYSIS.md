# T1059.001-2: PowerShell — Run BloodHound from local disk

## Technique Context

T1059.001 (PowerShell) represents one of the most common execution techniques used by adversaries across the attack lifecycle. PowerShell's legitimate administrative capabilities, deep Windows integration, and ability to operate in memory make it attractive for both initial access and post-compromise activities. In this specific test, PowerShell is used to execute BloodHound, a popular Active Directory reconnaissance tool that maps domain relationships and attack paths. The detection community focuses heavily on PowerShell script block logging, command-line arguments, module loading patterns, and the execution of known offensive tools like BloodHound/SharpHound.

## What This Dataset Contains

The dataset captures a failed BloodHound execution attempt with rich telemetry across multiple channels. Security event 4688 shows the PowerShell process creation with the full command line: `"powershell.exe" & {import-module \"C:\AtomicRedTeam\atomics\..\ExternalPayloads\SharpHound.ps1\" try { Invoke-BloodHound -OutputDirectory $env:Temp } catch { $_; exit $_.Exception.HResult} Start-Sleep 5}`. The PowerShell process exits with error code 0x80131501, indicating the BloodHound execution failed.

PowerShell script block logging (EID 4104) captures the actual malicious content: `& {import-module "C:\AtomicRedTeam\atomics\..\ExternalPayloads\SharpHound.ps1" try { Invoke-BloodHound -OutputDirectory $env:Temp } catch { $_; exit $_.Exception.HResult} Start-Sleep 5}` and `{import-module "C:\AtomicRedTeam\atomics\..\ExternalPayloads\SharpHound.ps1" try { Invoke-BloodHound -OutputDirectory $env:Temp } catch { $_; exit $_.Exception.HResult} Start-Sleep 5}`.

Sysmon captures extensive process activity including the PowerShell child process creation (EID 1), .NET runtime and PowerShell module loading (EID 7), process access attempts (EID 10), named pipe creation (EID 17), and file system activity (EID 11). Notably, Sysmon EID 1 events show process creation for both `whoami.exe` and the child PowerShell process containing the BloodHound execution command.

## What This Dataset Does Not Contain

The dataset lacks evidence of successful BloodHound execution. No network connections from the BloodHound process are captured, no Active Directory query traffic is present, and no BloodHound output files (typically .json format) are created in the temp directory. The PowerShell process exits with an error (0x80131501), suggesting the SharpHound.ps1 module failed to load or execute properly, possibly due to Windows Defender interference or missing dependencies. The dataset also contains predominantly PowerShell logging boilerplate with many generic script blocks related to error handling rather than the actual BloodHound functionality.

## Assessment

This dataset provides excellent telemetry for detecting PowerShell-based tool execution attempts, even when they fail. The combination of Security 4688 command-line logging and PowerShell 4104 script block logging creates robust detection opportunities. Sysmon data adds valuable process lineage and behavioral indicators. However, the failed execution limits its utility for understanding complete BloodHound attack patterns or network-based detection opportunities. The data is strongest for endpoint-based detections focused on PowerShell abuse and tool staging rather than successful domain reconnaissance activity.

## Detection Opportunities Present in This Data

1. **PowerShell Script Block Content Analysis** - EID 4104 events containing "import-module" combined with paths to "SharpHound.ps1" or "BloodHound" references
2. **Command Line Pattern Matching** - Security EID 4688 detecting PowerShell processes with command lines containing "Invoke-BloodHound" or SharpHound module imports
3. **PowerShell Module Loading** - Sysmon EID 7 showing System.Management.Automation.dll loading in conjunction with suspicious script execution
4. **Process Tree Analysis** - Multiple PowerShell child processes spawned in rapid succession, particularly when combined with reconnaissance tools
5. **File Access Patterns** - PowerShell processes attempting to access or import .ps1 files from external payload directories
6. **Named Pipe Creation** - Sysmon EID 17 showing PowerShell-related named pipes created during tool execution attempts
7. **Process Access Events** - Sysmon EID 10 showing PowerShell processes accessing other processes with high-level permissions (0x1FFFFF)
8. **Execution Policy Bypass** - PowerShell EID 4103 showing Set-ExecutionPolicy with "Bypass" parameter
