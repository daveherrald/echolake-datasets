# T1003.001-11: LSASS Memory — Dump LSASS with createdump.exe from .Net v5

## Technique Context

T1003.001 (LSASS Memory) is a critical credential access technique where attackers dump the memory of the Local Security Authority Subsystem Service (lsass.exe) to extract plaintext passwords, NTLM hashes, Kerberos tickets, and other authentication secrets. This technique is fundamental to Windows post-exploitation and lateral movement. The detection community focuses heavily on monitoring process access to LSASS with suspicious access rights (particularly PROCESS_VM_READ), unusual tools accessing LSASS, and the creation of memory dump files. This specific test attempts to use .NET Core's `createdump.exe` utility, which is a less commonly monitored tool compared to traditional dumping utilities like ProcDump or Mimikatz.

## What This Dataset Contains

This dataset captures a failed LSASS dumping attempt. The PowerShell command from Security event 4688 shows the intended attack: `"powershell.exe" & {$exePath = resolve-path \"$env:ProgramFiles\dotnet\shared\Microsoft.NETCore.App\5*\createdump.exe\"& \"$exePath\" -u -f $env:Temp\dotnet-lsass.dmp (Get-Process lsass).id}`. However, PowerShell event 4103 reveals the technique failed immediately: `NonTerminatingError(Resolve-Path): "Cannot find path 'C:\Program Files\dotnet\shared\Microsoft.NETCore.App' because it does not exist."` — the .NET 5 runtime is not installed on the target system.

The successful execution paths include multiple PowerShell processes (PIDs 5892, 6188, 4200, 2288) with extensive .NET Framework loading captured in Sysmon EID 7 events. The command successfully enumerated the LSASS process via `Get-Process lsass` as shown in PowerShell EID 4103 events, demonstrating that process enumeration succeeded but the dump tool was unavailable.

Sysmon EID 10 (Process Access) events show PowerShell accessing whoami.exe (PID 1824) and another PowerShell process (PID 4200) with PROCESS_ALL_ACCESS (0x1FFFFF), but critically, no access to lsass.exe is recorded, confirming the technique never progressed to the actual memory dumping stage.

## What This Dataset Does Not Contain

This dataset lacks the primary telemetry expected for successful LSASS memory dumping: no Sysmon EID 10 events showing process access to lsass.exe, no file creation events for dump files in %TEMP%, and no execution of createdump.exe itself (which would generate Sysmon EID 1 if the sysmon-modular config matched it). The test environment lacks .NET Core 5, causing immediate failure before any sensitive operations. There are no Windows Defender alerts or blocks since the technique never reached execution of the actual dumping tool. The dataset also contains no network activity or additional persistence mechanisms that might follow successful credential extraction.

## Assessment

This dataset provides limited utility for detection engineering focused on successful LSASS dumping, as the technique fails at the tool discovery phase. However, it offers valuable insights into attack preparation and reconnaissance phases. The PowerShell script block logging (EID 4104) and command invocation logging (EID 4103) capture the complete attack intent and methodology, making it useful for behavioral detection of LSASS dumping attempts regardless of success. The process access patterns and .NET Framework loading events provide baseline telemetry for PowerShell-based credential access attempts. For comprehensive LSASS dumping detection development, this dataset would be stronger if it included a successful execution with .NET 5 installed to capture the complete attack chain.

## Detection Opportunities Present in This Data

1. **PowerShell Script Block Analysis**: Monitor EID 4104 for script blocks containing "createdump.exe", "lsass", and dump file creation patterns like `$env:Temp\*.dmp`.

2. **Command Line Pattern Detection**: Alert on Security EID 4688 command lines containing combinations of "resolve-path", ".NET", "createdump.exe", and "lsass" process references.

3. **PowerShell Cmdlet Sequence Detection**: Monitor PowerShell EID 4103 for `Resolve-Path` followed by `Get-Process lsass` within the same PowerShell session, indicating reconnaissance for LSASS dumping tools.

4. **Tool Discovery Failure Analysis**: Track `NonTerminatingError` events in PowerShell logs mentioning credential access tools or paths, as failed tool discovery often precedes alternative technique attempts.

5. **Process Enumeration for Sensitive Targets**: Alert on PowerShell `Get-Process` invocations specifically targeting "lsass" as captured in the ParameterBinding events.

6. **Suspicious PowerShell .NET Framework Loading**: Correlate multiple Sysmon EID 7 events loading .NET assemblies in PowerShell processes with credential access-related command line arguments.

7. **Environment Reconnaissance Detection**: Monitor for PowerShell scripts attempting to locate credential dumping tools in standard installation paths like `$env:ProgramFiles\dotnet\shared\Microsoft.NETCore.App\`.
