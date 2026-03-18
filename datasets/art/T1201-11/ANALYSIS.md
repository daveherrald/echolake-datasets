# T1201-11: Password Policy Discovery — Use of SecEdit.exe to export the local security policy

## Technique Context

Password Policy Discovery (T1201) involves adversaries gathering information about the password policies of compromised systems to understand authentication requirements and security controls. This technique is crucial for attackers planning credential-based attacks, as understanding password complexity requirements, lockout thresholds, and aging policies helps optimize brute-force attacks and credential stuffing campaigns.

The specific variant tested here uses `secedit.exe`, a legitimate Windows security configuration tool, to export local security policy settings including password policies. This approach is particularly valuable to attackers because secedit can extract comprehensive security configuration data in a structured format, and its use appears legitimate in enterprise environments where security auditing is common. Detection engineers focus on monitoring secedit execution patterns, especially when invoked with policy export parameters, and the creation of policy export files in unusual locations.

## What This Dataset Contains

The dataset captures a clean execution of secedit.exe for password policy discovery through the following process chain:

**Process Execution Chain:**
- PowerShell (PID 20780) → cmd.exe (PID 21176) → secedit.exe (PID 16764)
- Security 4688 events show: `"cmd.exe" /c secedit.exe /export /areas SECURITYPOLICY /cfg output_mysecpol.txt`
- Security 4688 events show: `secedit.exe  /export /areas SECURITYPOLICY /cfg output_mysecpol.txt`

**Key Command Line:** The technique executes `secedit.exe /export /areas SECURITYPOLICY /cfg output_mysecpol.txt` which exports local security policy including password requirements.

**File Operations:** Sysmon EID 11 events capture:
- Creation of temporary file `C:\Windows\security\sce45037.tmp` by secedit.exe
- Creation of output file `C:\Windows\Temp\output_mysecpol.txt` containing the exported policy

**Process Access:** Sysmon EID 10 events show PowerShell accessing both cmd.exe and whoami.exe processes with full access rights (0x1FFFFF), indicating the test framework's process monitoring behavior.

**Privilege Usage:** Security EID 4703 shows PowerShell enabling multiple high-privilege tokens including SeSecurityPrivilege and SeBackupPrivilege, required for security policy access.

## What This Dataset Does Not Contain

The dataset lacks several elements that would strengthen detection coverage:

**Network Activity:** No network connections are captured, missing potential indicators of policy data exfiltration.

**File Content Analysis:** While file creation events are logged, the actual content of the exported security policy file is not captured in the telemetry.

**Registry Interaction:** Secedit reads security policy from the registry, but no registry access events are present, likely filtered by the Sysmon configuration.

**User Context Indicators:** The execution occurs under SYSTEM context, which may not reflect typical adversary usage patterns where attackers often operate under standard user accounts.

## Assessment

This dataset provides excellent foundational telemetry for detecting secedit-based password policy discovery. The Security channel's process creation events with command-line logging offer the primary detection opportunity, clearly showing the secedit execution with policy export parameters. The Sysmon file creation events add valuable context by showing both the temporary working files and the final output location.

The data quality is strong for building detections around process execution patterns and file creation behaviors. However, the SYSTEM execution context and lack of registry/network telemetry somewhat limits the dataset's representation of real-world attack scenarios where privilege levels and lateral movement patterns would differ.

## Detection Opportunities Present in This Data

1. **Secedit Process Creation with Export Parameters** - Monitor Security EID 4688 for secedit.exe execution with /export and /areas SECURITYPOLICY arguments, indicating security policy extraction attempts.

2. **Command Line Pattern Matching** - Detect the specific pattern `secedit.exe /export /areas SECURITYPOLICY /cfg` which directly indicates password policy discovery activity.

3. **Suspicious File Creation in Security Directories** - Monitor Sysmon EID 11 for file creation in C:\Windows\security\ by secedit.exe, especially temporary files with random names.

4. **Policy Export File Creation** - Alert on creation of .txt or .cfg files by secedit.exe in temporary directories, as these likely contain exported security policy data.

5. **Process Chain Analysis** - Correlate PowerShell or cmd.exe spawning secedit.exe with export parameters, indicating potential scripted policy extraction.

6. **Privilege Escalation Context** - Monitor Security EID 4703 privilege adjustments (SeSecurityPrivilege, SeBackupPrivilege) in conjunction with secedit execution.

7. **Multiple Security Tool Usage** - Combine secedit detection with other enumeration tools (like whoami.exe seen in this data) to identify broader reconnaissance campaigns.
