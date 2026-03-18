# T1003.002-2: Security Account Manager — Registry parse with pypykatz

## Technique Context

T1003.002 (Security Account Manager) involves extracting credential material from the Windows Security Account Manager (SAM) database, which stores local user account passwords as NTLM hashes. Attackers commonly target the SAM for lateral movement and privilege escalation since these hashes can be cracked offline or used in pass-the-hash attacks. The SAM database is normally locked while Windows is running, so attackers typically use tools like Mimikatz, pypykatz, or reg.exe to extract credentials through memory access or registry parsing. Detection engineers focus on monitoring LSASS process access, registry access to SAM/SECURITY/SYSTEM hives, and the execution of known credential dumping tools. This specific test uses pypykatz, a Python implementation of Mimikatz functionality, attempting to parse LSA secrets from a live system.

## What This Dataset Contains

This dataset captures a pypykatz execution that appears to have failed. The Security event logs show the critical command execution in EID 4688: `"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\venv_t1003_002\Scripts\pypykatz" live lsa` with the cmd.exe process exiting with status 0x1 (failure). The process chain shows PowerShell (PID 1668) spawning cmd.exe (PID 6372) to execute pypykatz from a Python virtual environment.

Sysmon captures extensive process and image loading activity across three PowerShell instances (PIDs 2292, 1668, 5076) with .NET runtime loading events. Notably, Sysmon EID 10 events show PowerShell accessing both whoami.exe (PID 5368) and cmd.exe (PID 6372) with full access rights (0x1FFFFF), which could indicate process injection attempts or normal PowerShell process management.

The Security logs also capture a privilege adjustment event (EID 4703) where PowerShell enables multiple high-privilege tokens including SeDebugPrivilege, SeBackupPrivilege, and SeRestorePrivilege - privileges commonly required for credential access operations.

PowerShell script block logging contains only framework boilerplate with Set-StrictMode and Set-ExecutionPolicy commands, indicating the actual pypykatz execution occurred through the spawned cmd.exe process rather than PowerShell cmdlets.

## What This Dataset Does Not Contain

This dataset lacks the telemetry that would indicate successful credential extraction. There are no Sysmon EID 10 events showing LSASS process access, which would be the primary indicator of successful SAM/LSA credential harvesting. The cmd.exe process failure (exit code 0x1) suggests pypykatz encountered an error, possibly due to insufficient privileges or Windows Defender interference, though no explicit blocking events are visible.

The dataset contains no file creation events for credential dumps, no network connections that might indicate credential exfiltration, and no registry access events to the SAM/SECURITY/SYSTEM hives that pypykatz would typically target. The absence of Sysmon EID 13 (registry value set) or EID 12 (registry object create/delete) events suggests the tool didn't successfully interact with the targeted registry locations.

## Assessment

This dataset provides moderate value for detection engineering, primarily as an example of credential dumping tool execution patterns rather than successful technique completion. The Security 4688 events with command-line logging offer the strongest detection opportunity, clearly showing pypykatz execution with the "live lsa" arguments. The privilege escalation event (EID 4703) demonstrates how attackers prepare for credential access operations by enabling necessary privileges.

The Sysmon process access events (EID 10) show interesting PowerShell behavior that could be relevant for behavioral detection, though they don't represent the core LSASS access pattern typically associated with this technique. The dataset would be significantly stronger if it contained successful pypykatz execution showing LSASS process access, registry interaction, or credential file output.

## Detection Opportunities Present in This Data

1. Command-line detection for pypykatz execution patterns in Security EID 4688 events, specifically looking for "pypykatz" strings with "live" and "lsa" arguments
2. Process chain analysis detecting cmd.exe spawned by PowerShell for credential dumping tool execution
3. Privilege escalation monitoring via Security EID 4703 events showing simultaneous enablement of SeDebugPrivilege, SeBackupPrivilege, and SeRestorePrivilege
4. Behavioral detection of PowerShell processes accessing multiple child processes with full access rights (Sysmon EID 10 with GrantedAccess 0x1FFFFF)
5. Python virtual environment path detection in command lines, indicating use of packaged attack tools
6. Process exit code monitoring for failed credential dumping attempts (cmd.exe exit status 0x1 following pypykatz execution)
7. File path detection for AtomicRedTeam and ExternalPayloads directory structures indicating test framework usage
