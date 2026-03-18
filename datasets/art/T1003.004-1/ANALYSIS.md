# T1003.004-1: LSA Secrets — Dumping LSA Secrets

## Technique Context

T1003.004 (LSA Secrets) is a credential access technique where attackers dump the Local Security Authority (LSA) secrets database to harvest credentials, service account passwords, cached domain credentials, and other sensitive authentication material. LSA secrets are stored in the Windows registry under `HKLM\SECURITY\Policy\Secrets` and contain various sensitive information including service account passwords, cached domain logon information, and machine account passwords.

Attackers commonly use tools like `reg save` to extract the LSA secrets registry hive, then parse the dumped data offline to extract credentials. This technique is frequently used in post-exploitation phases and lateral movement scenarios. The detection community focuses on monitoring registry access to the LSA secrets location, process access to LSASS, and the creation of suspicious registry dump files.

## What This Dataset Contains

This dataset captures an Atomic Red Team test execution attempting to dump LSA secrets using PsExec and the Windows `reg save` command. The key evidence includes:

Security event 4688 shows the critical command line: `"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\T1003.004\bin\PsExec.exe" -accepteula -s reg save HKLM\security\policy\secrets %temp%\secrets /y`

The process chain shows PowerShell (PID 5748) spawning cmd.exe (PID 5912) to execute the PsExec command. Security event 4703 captures privilege escalation with `SeBackupPrivilege` and `SeRestorePrivilege` being enabled on the PowerShell process - privileges required for accessing protected registry locations.

Sysmon event 1 captures both the `whoami.exe` execution for discovery and the cmd.exe process creation with the full command line showing the attempt to save the LSA secrets registry key. Sysmon event 10 shows process access attempts from PowerShell to both whoami.exe and cmd.exe with full access rights (0x1FFFFF).

## What This Dataset Does Not Contain

Critically, this dataset shows the attempt but not successful completion of LSA secrets dumping. The cmd.exe process exits with status code 0x1 (failure), indicating the `reg save` operation was blocked. There are no Sysmon file creation events (EID 11) showing the creation of a `secrets` dump file in %temp%, which would be expected if the technique succeeded.

The dataset lacks any registry access events (Sysmon EID 12/13) that would show direct manipulation of the LSA secrets registry location. No LSASS process access events are present, and there's no evidence of successful credential extraction or parsing tools being executed. The absence of a successful dump file creation suggests Windows Defender or access controls prevented the registry extraction.

## Assessment

This dataset provides excellent telemetry for detecting LSA secrets dumping attempts, particularly the command-line evidence and privilege escalation indicators. The Security channel captures the full attack command line, while Sysmon provides process tree context and access patterns. However, since the technique was blocked before completion, the dataset doesn't contain post-successful-dump artifacts that would be valuable for detecting more sophisticated variants.

The privilege escalation evidence (4703) is particularly valuable as it shows the enabling of backup/restore privileges that are commonly required for this technique. The process access events provide additional behavioral indicators that could supplement command-line based detections.

## Detection Opportunities Present in This Data

1. **Command line detection** - Security 4688 contains `reg save HKLM\security\policy\secrets` command line, a high-fidelity indicator of LSA secrets dumping attempts

2. **Privilege escalation monitoring** - Security 4703 shows SeBackupPrivilege and SeRestorePrivilege being enabled, which are required for accessing protected registry locations

3. **Process tree analysis** - PowerShell spawning cmd.exe with reg.exe commands targeting sensitive registry locations indicates credential access behavior

4. **PsExec usage detection** - Command line contains PsExec.exe being used with `-s` flag for SYSTEM privileges and reg save operations

5. **Registry path targeting** - Monitor for any processes accessing or attempting to save `HKLM\security\policy\secrets` registry location

6. **Process access patterns** - Sysmon EID 10 shows PowerShell accessing child processes with full rights, which may indicate process injection or monitoring behavior

7. **Suspicious file locations** - Commands referencing ExternalPayloads directories or AtomicRedTeam paths indicate test tool usage

8. **Failed execution detection** - Process exit codes of 0x1 combined with credential access command lines may indicate blocked attack attempts
