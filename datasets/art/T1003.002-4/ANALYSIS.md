# T1003.002-4: Security Account Manager — PowerDump Hashes and Usernames from Registry

## Technique Context

T1003.002 (Security Account Manager) involves extracting credential material from the Windows Security Account Manager (SAM) database, which stores local user account password hashes. This is a foundational credential access technique that attackers use to obtain password hashes for offline cracking or pass-the-hash attacks. PowerDump is a well-known PowerShell implementation that reads registry keys containing SAM data to extract user accounts and their NTLM hashes. The detection community focuses heavily on monitoring registry access to SAM-related keys (HKLM\SAM, HKLM\SECURITY), process access patterns to LSASS, and the presence of credential dumping tools. This technique requires elevated privileges (typically SYSTEM) since the SAM database is protected by Windows security mechanisms.

## What This Dataset Contains

The dataset shows PowerShell executing the PowerDump technique with clear evidence in the command line. Security EID 4688 captures the PowerShell process creation with the full command: `"powershell.exe" & {Write-Host \"STARTING TO SET BYPASS and DISABLE DEFENDER REALTIME MON\" -fore green; Import-Module \"C:\AtomicRedTeam\atomics\..\ExternalPayloads\PowerDump.ps1\"; Invoke-PowerDump}`. The PowerShell events (EID 4104) show script block creation for importing the PowerDump module at `C:\AtomicRedTeam\atomics\..\ExternalPayloads\PowerDump.ps1` and executing `Invoke-PowerDump`. Sysmon captures the complete process tree with process creation events (EID 1) for both the parent PowerShell process and the child PowerShell process executing PowerDump. Security EID 4703 shows privilege adjustment events where the PowerShell process enables critical privileges including `SeBackupPrivilege`, `SeRestorePrivilege`, and `SeSecurityPrivilege` - privileges commonly required for registry access to protected SAM data. All processes execute under NT AUTHORITY\SYSTEM context with full administrative privileges.

## What This Dataset Does Not Contain

The dataset lacks the most critical telemetry for detecting SAM credential extraction. There are no registry access events showing reads to `HKLM\SAM\SAM\Domains\Account\Users` or `HKLM\SECURITY\Policy\Secrets` keys where password hashes are stored. The Sysmon configuration appears to exclude registry events (no EID 12/13), which are essential for detecting this technique. No file creation events show credential dumps being written to disk. There's no evidence of LSASS process access (while Sysmon EID 10 shows some process access, it's to whoami.exe and another PowerShell process, not LSASS). The PowerShell script block logging only captures the test framework commands and Import-Module/Invoke-PowerDump calls, but not the actual PowerDump function content that would show registry access patterns. Windows Defender may have blocked the actual credential extraction while allowing the process creation and module import to proceed.

## Assessment

This dataset has limited utility for building comprehensive SAM credential extraction detections. While it provides excellent process-level telemetry (command lines, parent-child relationships, privilege escalation), it lacks the registry access events that are fundamental to detecting this technique. The command line evidence is valuable but insufficient alone, as attackers can easily modify command syntax or use encoded commands. For detection engineering, this dataset is more useful for identifying PowerDump deployment patterns rather than the credential extraction activity itself. A stronger dataset would include Sysmon registry events showing SAM key access, object access auditing for sensitive registry locations, and potentially LSASS access monitoring.

## Detection Opportunities Present in This Data

1. **PowerShell command line detection** - Security EID 4688 contains clear indicators: "Import-Module" + "PowerDump.ps1" + "Invoke-PowerDump" command pattern that can be matched with regex or string contains logic

2. **PowerShell script block analysis** - PowerShell EID 4104 events show PowerDump module import and function invocation that can be detected through script block content monitoring for "PowerDump" strings

3. **Suspicious privilege adjustment** - Security EID 4703 shows enabling of backup/restore/security privileges by PowerShell, which is unusual for normal PowerShell usage and indicates potential credential access preparation

4. **Process ancestry detection** - Sysmon EID 1 shows PowerShell spawning child PowerShell processes with credential dumping commands, creating a detectable parent-child relationship pattern

5. **External payload path detection** - Command lines and script blocks reference "ExternalPayloads\PowerDump.ps1" indicating use of external attack tooling that can be detected through file path analysis

6. **SYSTEM context PowerShell execution** - All PowerShell processes run as NT AUTHORITY\SYSTEM, which combined with credential-related commands provides a high-confidence detection opportunity for unauthorized credential access attempts
