# T1207-1: Rogue Domain Controller — DCShadow (Active Directory)

## Technique Context

T1207 Rogue Domain Controller represents one of the most sophisticated Active Directory attacks, where adversaries with sufficient privileges establish a temporary rogue domain controller to modify AD objects without leaving traditional audit trails. The DCShadow attack, popularized by Mimikatz, requires SYSTEM-level privileges and specific Active Directory rights to register a computer as a domain controller, then inject malicious changes through normal AD replication processes. This technique bypasses standard security monitoring since the changes appear as legitimate replication traffic. Detection engineers focus on monitoring for unexpected domain controller registrations, unusual replication traffic patterns, privilege escalation to SYSTEM context, and the execution of tools like Mimikatz that implement DCShadow functionality.

## What This Dataset Contains

This dataset captures a DCShadow attack simulation using Mimikatz executed through PowerShell. The core attack sequence is visible in Security event 4688, showing PowerShell executing with a command line containing `lsadump::dcshadow /object:bruce.wayne /attribute:badpwdcount /value:9999`, attempting to modify the badpwdcount attribute of a user object. The attack attempts to use PsExec to execute Mimikatz with SYSTEM privileges: `"/c 'C:\AtomicRedTeam\atomics\..\ExternalPayloads\PSTools\PsExec.exe' /accepteula -d -s C:\AtomicRedTeam\atomics\..\ExternalPayloads\mimikatz\x64\mimikatz.exe"`. However, the cmd.exe process (PID 35904) exits with status 0x1, indicating failure.

The PowerShell script block logging (event 4104) reveals the complete attack structure: establishing a fake DC server, waiting for readiness, triggering replication with `lsadump::dcshadow /push`, and attempting to read output from a log file at `C:\AtomicRedTeam\atomics\..\ExternalPayloads\art-T1207-mimikatz-DC.log`. Sysmon captures the process creation chain: PowerShell (PID 24404) spawning another PowerShell instance (PID 36348) with the DCShadow script, then cmd.exe (PID 35904) attempting to execute PsExec. Security event 4703 shows token privilege adjustment for the PowerShell process, enabling multiple high-privilege rights including SeBackupPrivilege and SeRestorePrivilege.

## What This Dataset Does Not Contain

Critically, this dataset lacks evidence of successful DCShadow execution. The cmd.exe process exits with error code 0x1, and there are no Sysmon ProcessCreate events for PsExec or Mimikatz, suggesting Windows Defender or system restrictions blocked the execution. The dataset contains no network traffic (DNS queries, LDAP connections, or replication traffic) that would indicate actual communication with domain controllers. There are no registry modifications related to domain controller registration, no service installations, and no evidence of the temporary domain controller becoming active. The promised output file operations (reading from the Mimikatz log) are not captured in the file creation events, indicating the attack components never executed successfully.

## Assessment

This dataset provides excellent telemetry for detecting DCShadow *attempts* but limited insight into successful attacks. The PowerShell script block logging comprehensively captures the attack logic and Mimikatz command lines, while Security 4688 events preserve the full command execution chain with arguments. The privilege adjustment logging (4703) shows the elevation of sensitive privileges necessary for the attack. However, the lack of successful execution means defenders won't see the more advanced indicators like domain controller registration events, replication traffic anomalies, or LDAP modifications that characterize a completed DCShadow attack. For detection engineering focused on early-stage indicators and attack attempts, this data is highly valuable. For understanding post-exploitation persistence mechanisms, it's insufficient.

## Detection Opportunities Present in This Data

1. **Mimikatz DCShadow Module Detection** - Monitor PowerShell script blocks and command lines for `lsadump::dcshadow` patterns, particularly when combined with `/object:`, `/attribute:`, and `/push` parameters

2. **SYSTEM Privilege Escalation for AD Operations** - Alert on PowerShell processes running as SYSTEM that enable multiple high-privilege rights simultaneously (SeBackupPrivilege, SeRestorePrivilege, SeSecurityPrivilege)

3. **PsExec with Mimikatz Execution Pattern** - Detect command lines containing PsExec with `/accepteula -d -s` flags followed by mimikatz.exe execution paths

4. **Suspicious PowerShell Process Spawning** - Monitor for PowerShell processes creating child PowerShell instances with embedded DCShadow-related script content

5. **Token Rights Adjustment Baseline Deviation** - Establish baselines for normal privilege usage and alert on unusual combinations of rights being enabled by PowerShell processes

6. **Failed Process Execution in AD Attack Context** - Correlate cmd.exe exit status 0x1 with PowerShell scripts containing Active Directory attack keywords as potential blocked attack attempts
