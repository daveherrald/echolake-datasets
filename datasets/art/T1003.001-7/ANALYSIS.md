# T1003.001-7: LSASS Memory — LSASS read with pypykatz

## Technique Context

T1003.001 LSASS Memory represents one of the most critical credential access techniques in the MITRE ATT&CK framework. Attackers target the Local Security Authority Subsystem Service (LSASS) process to extract plaintext passwords, password hashes, and Kerberos tickets from memory. The pypykatz tool, a pure Python implementation of Mimikatz functionality, provides attackers with a cross-platform method to perform LSASS memory dumping and credential extraction. Unlike traditional tools that require native compilation, pypykatz can be deployed in Python environments and offers similar capabilities for harvesting credentials from LSASS memory. Detection engineers focus on monitoring process access events to LSASS (particularly with high-privilege access rights), unusual process creations involving credential dumping tools, and the loading of specific DLLs that enable memory access functionality.

## What This Dataset Contains

This dataset captures a pypykatz execution attempting to read LSASS memory, showing both the execution chain and Windows Defender's intervention. The primary execution sequence begins with PowerShell (PID 5348) creating a cmd.exe process (PID 6344) with the command line `"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\venv_t1003_001\Scripts\pypykatz" live lsa`. Security event 4688 records this process creation with full command-line details. The cmd.exe process exits with status 0x1, indicating failure.

The dataset shows Sysmon EID 10 (Process Access) events where PowerShell accesses both whoami.exe (PID 1340) and cmd.exe (PID 6344) with full access rights (0x1FFFFF). These process access events include detailed call traces showing .NET Framework components and System.Management.Automation.ni.dll in the execution path.

Sysmon EID 7 events capture the loading of security-relevant DLLs including Windows Defender components (MpOAV.dll, MpClient.dll) and .NET Framework libraries (mscoree.dll, mscoreei.dll, clr.dll, clrjit.dll). Security event 4703 records privilege escalation with SeDebugPrivilege among the enabled privileges for the PowerShell process.

## What This Dataset Does Not Contain

The dataset lacks the critical LSASS process access events that would indicate successful credential dumping. There are no Sysmon EID 10 events showing pypykatz or its parent processes accessing lsass.exe, which would be the primary indicator of this technique's success. The cmd.exe exit status of 0x1 suggests Windows Defender blocked the pypykatz execution before it could access LSASS memory.

The dataset contains no file creation events for credential dump files, memory dumps, or other artifacts typically associated with successful LSASS harvesting. There are no network connections that might indicate credential exfiltration. The Security channel lacks any 4656/4658 object access events for LSASS process handles, though this could be due to audit policy configuration rather than technique failure.

## Assessment

This dataset provides moderate value for detection engineering, primarily demonstrating Windows Defender's effectiveness at blocking pypykatz execution rather than showing the technique's successful completion. The process creation events with full command lines offer excellent detection opportunities for identifying pypykatz deployment attempts. The privilege escalation events and process access patterns provide useful behavioral indicators, though they represent preliminary actions rather than the core LSASS access.

The dataset would be stronger with LSASS process access events showing the technique's success, credential dump file artifacts, or Windows Defender's specific blocking mechanisms. However, it effectively demonstrates real-world defensive posture where endpoint protection prevents many credential harvesting attempts from completing.

## Detection Opportunities Present in This Data

1. **Command Line Detection**: Security EID 4688 events containing "pypykatz" and "live lsa" parameters in command lines, indicating credential harvesting tool execution attempts.

2. **Process Chain Analysis**: PowerShell spawning cmd.exe with credential dumping tool paths, particularly from AtomicRedTeam or ExternalPayloads directories.

3. **Privilege Escalation Monitoring**: Security EID 4703 events showing SeDebugPrivilege and other sensitive privileges being enabled by PowerShell processes.

4. **Process Access Pattern Recognition**: Sysmon EID 10 events with 0x1FFFFF (full access) granted access rights, especially from PowerShell or script interpreter processes.

5. **Defensive DLL Loading**: Sysmon EID 7 events showing Windows Defender modules (MpOAV.dll, MpClient.dll) being loaded, indicating security product engagement.

6. **Failed Process Execution**: Security EID 4689 events with non-zero exit codes from processes launched with credential dumping tool command lines, suggesting blocked execution attempts.
