# T1087.002-5: Domain Account — Adfind -Listing password policy

## Technique Context

T1087.002 (Account Discovery: Domain Account) represents a critical early-stage reconnaissance technique where attackers enumerate domain accounts to understand the target environment's user landscape. AdFind is a legitimate command-line tool for querying Active Directory that has become a staple in both red team and real-world attack scenarios. When attackers use AdFind to query password policy attributes (lockoutduration, lockoutthreshold, maxpwdage, etc.), they're gathering intelligence to inform credential attacks, understanding password complexity requirements, lockout thresholds, and account aging policies. This specific test demonstrates password policy enumeration, which helps attackers craft more effective brute force and password spray campaigns while avoiding account lockouts.

The detection community focuses heavily on AdFind usage due to its prevalence in ransomware and APT campaigns. Key detection points include process execution with AD-specific command line parameters, LDAP queries with base scope searches, and the tool's characteristic pattern of querying multiple password policy attributes in sequence.

## What This Dataset Contains

This dataset captures a failed AdFind execution through PowerShell process chains. The Security channel shows the complete execution flow in Security 4688 events: PowerShell (PID 24648) spawns cmd.exe with the command line `"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\AdFind.exe" -default -s base lockoutduration lockoutthreshold lockoutobservationwindow maxpwdage minpwdage minpwdlength pwdhistorylength pwdproperties`. The cmd.exe process exits with status 0x1, indicating failure.

Sysmon captures the process creation of both whoami.exe (EID 1) and cmd.exe (EID 1), along with PowerShell's process access attempts (Sysmon EID 10) showing GrantedAccess 0x1FFFFF to both child processes. Three separate PowerShell processes are instrumented with extensive .NET runtime DLL loading (mscoree.dll, mscoreei.dll, clr.dll) and PowerShell-specific assemblies (System.Management.Automation.ni.dll).

The PowerShell channel contains only test framework boilerplate - Set-StrictMode scriptblocks and Set-ExecutionPolicy Bypass commands (EID 4103/4104) - with no evidence of the actual AdFind command execution or results.

## What This Dataset Does Not Contain

Most critically, this dataset lacks any evidence of successful AdFind execution or LDAP query activity. There are no Sysmon ProcessCreate events for AdFind.exe itself, suggesting either Windows Defender blocked the execution or the binary was missing from the expected path. The sysmon-modular config's include-mode filtering would typically capture AdFind.exe as it's a known LOLBin, so the absence indicates execution failure rather than logging gaps.

The dataset contains no network telemetry (no Sysmon EID 3 network connections) that would show LDAP queries to domain controllers on port 389/636. There are no authentication events (Security 4624/4625) showing service account usage for domain queries. DNS queries (Sysmon EID 22) for domain controller resolution are also absent, and there are no file creation events showing AdFind output dumps.

## Assessment

This dataset has limited utility for AdFind detection development since it captures only a failed execution attempt. The process command line in Security 4688 provides the most valuable detection artifact, showing the characteristic AdFind syntax targeting password policy attributes. The PowerShell execution chain is well-documented across Security and Sysmon channels, making it useful for understanding the delivery mechanism.

However, the lack of successful execution significantly reduces the dataset's value for detection engineering. Real AdFind usage generates distinctive LDAP traffic patterns, authentication events, and often creates output files - none of which are present here. The dataset would be significantly stronger with successful execution showing actual domain controller communication and query results.

## Detection Opportunities Present in This Data

1. **AdFind Command Line Detection** - Security EID 4688 command line containing "AdFind.exe" with password policy parameters (lockoutduration, lockoutthreshold, maxpwdage, minpwdage, pwdhistorylength, pwdproperties)

2. **PowerShell-to-CMD-to-AdFind Process Chain** - Sequence of powershell.exe → cmd.exe → AdFind.exe execution pattern in Security 4688 events

3. **Suspicious Command Line Pattern** - Detection of "-default -s base" LDAP scope parameters combined with multiple password policy attribute names

4. **External Payload Path Detection** - File path containing "AtomicRedTeam\atomics\..\ExternalPayloads\AdFind.exe" indicating potential red team tooling

5. **PowerShell Process Access to Child Processes** - Sysmon EID 10 showing PowerShell accessing spawned processes with full access rights (0x1FFFFF)

6. **Failed Process Execution** - Security EID 4689 showing cmd.exe exit status 0x1, potentially indicating blocked or failed tool execution
