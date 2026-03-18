# T1219-6: Remote Access Tools — Ammyy Admin Software Execution

## Technique Context

T1219 Remote Access Tools represents adversary use of legitimate remote administration software for command and control purposes. Attackers leverage tools like TeamViewer, LogMeIn, VNC, and Ammyy Admin because they appear benign to users and security tools, often bypassing network restrictions and security controls. Ammyy Admin specifically has been observed in numerous campaigns, including cryptocurrency theft, banking trojans, and APT operations.

The detection community focuses on identifying unauthorized remote access tool deployments, monitoring for suspicious download/execution patterns, tracking command-line arguments that enable stealth modes, and correlating network traffic with known RAT signatures. Key indicators include executables dropped to unusual locations, silent installation attempts, and persistence mechanisms.

## What This Dataset Contains

This dataset captures an attempted execution of Ammyy Admin via PowerShell that fails due to a missing file. The Security channel shows the complete process chain in EID 4688 events: the parent PowerShell (PID 44388) spawning a child PowerShell (PID 28028) with command line `"powershell.exe" & {Start-Process \"C:\AtomicRedTeam\atomics\..\ExternalPayloads\ammyy.exe\"}`. 

The PowerShell channel contains the actual execution command in EID 4104: `& {Start-Process "C:\AtomicRedTeam\atomics\..\ExternalPayloads\ammyy.exe"}` and the resulting error in EID 4100: `Error Message = This command cannot be run due to the error: The system cannot find the file specified.` with `Fully Qualified Error ID = InvalidOperationException,Microsoft.PowerShell.Commands.StartProcessCommand`.

Sysmon captures extensive PowerShell process telemetry including EID 1 ProcessCreate for both the whoami.exe reconnaissance command and the child PowerShell process, plus EID 7 ImageLoad events showing .NET runtime loading, PowerShell automation libraries, and Windows Defender integration. EID 10 ProcessAccess events show the parent PowerShell accessing both child processes with full access rights (0x1FFFFF).

## What This Dataset Does Not Contain

Since the ammyy.exe file doesn't exist at the specified path, there's no actual Ammyy Admin execution, network connections, or persistence mechanisms. We see no Sysmon EID 3 NetworkConnect events, no file operations related to the RAT payload, and no registry modifications for persistence. The technique telemetry is limited to the attempt rather than successful deployment.

No Sysmon ProcessCreate events are captured for the actual ammyy.exe execution because the file doesn't exist. The sysmon-modular config's include-mode filtering for ProcessCreate only captures known-suspicious patterns, but the Security channel provides complete process auditing showing the failed execution attempt.

## Assessment

This dataset provides excellent telemetry for detecting Remote Access Tool deployment attempts via PowerShell, even when the execution fails. The combination of Security 4688 process auditing with complete command lines and PowerShell script block logging (EID 4104) creates a comprehensive detection surface. The error message in PowerShell EID 4100 specifically indicates a file not found condition, which is valuable for understanding failed RAT deployments.

The Sysmon telemetry adds valuable context around process relationships and .NET/PowerShell automation loading patterns. While the technique doesn't complete successfully, the attempt generates significant forensic evidence that would be present in real-world scenarios where attackers try to execute missing or quarantined RAT payloads.

## Detection Opportunities Present in This Data

1. PowerShell script block execution of Start-Process with external payload paths (`Start-Process "C:\AtomicRedTeam\atomics\..\ExternalPayloads\ammyy.exe"` in EID 4104)

2. Process creation with suspicious PowerShell command lines referencing RAT executables (Security EID 4688 command line containing ammyy.exe path)

3. PowerShell error patterns indicating failed RAT execution attempts (EID 4100 InvalidOperationException with "system cannot find the file specified")

4. Parent-child PowerShell process relationships with Start-Process cmdlet usage (Sysmon EID 1 with PowerShell spawning from PowerShell)

5. Process access patterns showing PowerShell accessing newly created child processes with full rights (Sysmon EID 10 with GrantedAccess 0x1FFFFF)

6. File path patterns referencing common RAT installation directories or external payload locations (`ExternalPayloads` directory structure)

7. PowerShell execution policy bypass combined with external executable references (EID 4103 Set-ExecutionPolicy Bypass correlated with Start-Process commands)
