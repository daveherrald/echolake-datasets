# T1021.003-1: Distributed Component Object Model — PowerShell Lateral Movement using MMC20

## Technique Context

T1021.003 represents lateral movement through Distributed Component Object Model (DCOM) exploitation, where attackers leverage Windows COM objects to execute commands on remote systems. The MMC20.Application object is a particularly popular DCOM endpoint because it's widely available and provides direct command execution capabilities through its ExecuteShellCommand method. This technique allows attackers to move laterally across networks while appearing as legitimate administrative activity, since MMC (Microsoft Management Console) is a standard Windows component. Detection engineering focuses on identifying unusual process creation patterns from mmc.exe, PowerShell scripts that instantiate COM objects, and cross-process access patterns that suggest DCOM abuse.

## What This Dataset Contains

This dataset captures a complete DCOM lateral movement execution using the MMC20.Application COM object. The attack begins with PowerShell executing the malicious command: `[activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.application","localhost")).Document.ActiveView.ExecuteShellCommand("c:\windows\system32\calc.exe", $null, $null, "7")`. 

Security event 4688 shows the initial PowerShell process (PID 6820) with the full command line containing the DCOM instantiation. Sysmon event 1 captures the same process creation with additional context including file hashes and parent process information. The technique successfully spawns mmc.exe (PID 2000) via svchost.exe with the "-Embedding" command line argument, which is the characteristic signature of DCOM activation. Subsequently, mmc.exe creates calc.exe (PID 3208), demonstrating successful command execution through the DCOM channel.

PowerShell script block logging (event 4104) captures the exact malicious payload twice: once as the full script block and once within a parsed context. Multiple Sysmon process access events (EID 10) show the PowerShell process accessing both the whoami.exe and the spawned PowerShell processes with extensive access rights (0x1FFFFF), indicating potential injection or monitoring activity.

## What This Dataset Does Not Contain

This dataset demonstrates local DCOM execution rather than true lateral movement across network boundaries. The technique targets "localhost" instead of a remote system, so we don't see network authentication events, Kerberos ticket usage, or network connection establishment that would accompany actual lateral movement. The dataset also lacks any evidence of Windows Defender blocking or quarantining the activity, suggesting this benign test execution didn't trigger endpoint protection signatures. Additionally, there are no registry modifications or persistence mechanisms that might accompany a real-world DCOM attack campaign.

## Assessment

This dataset provides excellent telemetry for detecting DCOM abuse through multiple complementary data sources. The combination of Security 4688 command-line logging, Sysmon process creation events, and PowerShell script block logging creates multiple detection opportunities that would be difficult for attackers to evade simultaneously. The process genealogy from PowerShell → svchost.exe → mmc.exe → calc.exe clearly demonstrates the DCOM execution chain. While the localhost-only execution limits its value for detecting true lateral movement, the core technique signatures are well-represented and would apply to remote DCOM scenarios with additional network telemetry.

## Detection Opportunities Present in This Data

1. PowerShell script blocks containing `MMC20.Application`, `GetTypeFromProgID`, or `ExecuteShellCommand` method calls
2. Process creation events showing mmc.exe spawned with `-Embedding` command line parameter by svchost.exe
3. Unusual parent-child relationships where mmc.exe creates unexpected processes like calc.exe or cmd.exe
4. Security 4688 events with PowerShell command lines containing COM object instantiation patterns (`[activator]::CreateInstance`)
5. Sysmon process access events showing PowerShell accessing other processes with high-privilege access masks (0x1FFFFF)
6. Process creation chains involving PowerShell → System processes → mmc.exe → target executables
7. MMC processes loading urlmon.dll, which may indicate COM/DCOM activity
8. Multiple PowerShell processes created in rapid succession with similar command patterns
