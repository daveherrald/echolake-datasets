# T1003.003-9: NTDS — Create Volume Shadow Copy with diskshadow

## Technique Context

T1003.003 (NTDS) involves extracting credential material from the Active Directory database (NTDS.dit). This technique is critical for attackers performing lateral movement and domain escalation, as NTDS.dit contains password hashes for all domain accounts. The specific test variant uses `diskshadow.exe` to create a Volume Shadow Copy (VSS), allowing access to the locked NTDS.dit file while the domain controller is running. This approach is commonly used by sophisticated adversaries and penetration testers because diskshadow.exe is a legitimate Windows utility that can bypass basic application whitelisting. Detection engineers focus on monitoring diskshadow.exe execution, VSS creation events, and subsequent file access patterns to NTDS.dit locations.

## What This Dataset Contains

The execution shows PowerShell spawning cmd.exe with the command line `"cmd.exe" /c mkdir c:\exfil & diskshadow.exe /s C:\AtomicRedTeam\atomics\T1003.003\src\diskshadow.txt`. However, both cmd.exe processes (PIDs 1592 and 6168) exit with status 0x1, indicating failure. Security event 4688 captures the process creation with full command line visibility, while Sysmon EID 1 captures the cmd.exe creation due to its inclusion in the sysmon-modular filtering rules. The dataset contains privilege escalation evidence in Security EID 4703, showing PowerShell enabling multiple sensitive privileges including `SeBackupPrivilege` and `SeRestorePrivilege` - privileges commonly required for VSS operations. Process access events (Sysmon EID 10) show PowerShell accessing both whoami.exe and cmd.exe processes with full access rights (0x1FFFFF). The PowerShell channel contains only boilerplate Set-ExecutionPolicy and Set-StrictMode events without actual technique implementation.

## What This Dataset Does Not Contain

The dataset lacks the actual diskshadow.exe process creation, indicating it was either blocked by Windows Defender or failed before launch. There are no VSS-related events (typically found in System channel Event IDs 7036, 7040) that would indicate successful shadow copy creation. File creation events (Sysmon EID 11) only show PowerShell profile artifacts, not the expected NTDS.dit extraction or staging files in c:\exfil. Network events, registry modifications related to VSS configuration, and any successful credential extraction artifacts are absent. The missing diskshadow.exe execution suggests the technique was prevented before completion, likely due to endpoint protection blocking the operation.

## Assessment

This dataset provides limited value for detecting successful NTDS extraction but offers excellent visibility into the preparatory phases. The Security channel's command-line logging captures the full attack intent, while the privilege escalation events (EID 4703) demonstrate the sensitive privileges required for VSS operations. The process chain from PowerShell to cmd.exe is well-documented across multiple data sources. However, the technique's failure limits the dataset's utility for understanding post-execution phases like VSS enumeration, NTDS.dit copying, or credential parsing. The dataset is most valuable for detecting attempted NTDS extraction rather than successful completion.

## Detection Opportunities Present in This Data

1. **Command-line detection for diskshadow.exe execution** - Security EID 4688 shows `diskshadow.exe /s` with script file parameter, indicating automated VSS creation attempt

2. **Sensitive privilege escalation monitoring** - Security EID 4703 captures SeBackupPrivilege and SeRestorePrivilege enablement, which are required for NTDS access

3. **Process chain analysis** - PowerShell spawning cmd.exe with diskshadow.exe parameters indicates potential credential access activity

4. **Directory creation for staging** - Command line shows `mkdir c:\exfil` indicating preparation of extraction staging area

5. **PowerShell process access patterns** - Sysmon EID 10 shows PowerShell accessing spawned processes with full rights, potentially indicating process injection or monitoring behavior
