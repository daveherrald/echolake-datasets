# T1069.002-14: Domain Groups — Active Directory Enumeration with LDIFDE

## Technique Context

T1069.002 Domain Groups is a discovery technique where adversaries enumerate domain groups to understand the organizational structure, identify high-value targets, and map group memberships for privilege escalation paths. LDIFDE (LDAP Data Interchange Format Directory Exchange) is a Windows utility that can export Active Directory objects to LDIF format files, making it a legitimate but potentially suspicious tool for domain enumeration.

The detection community focuses on LDIFDE command-line patterns, unusual file creation locations, and processes making LDAP queries. This technique is particularly valuable to threat hunters because LDIFDE usage outside of administrative contexts often indicates reconnaissance activity, and the tool's output files contain sensitive organizational structure information.

## What This Dataset Contains

The dataset captures a PowerShell-initiated LDIFDE execution with the following key artifacts:

**Process Chain**: PowerShell → cmd.exe → ldifde.exe (inferred from command line)
- Security EID 4688: `"cmd.exe" /c ldifde.exe -f C:\Windows\temp\atomic_ldifde.txt -p subtree`
- Sysmon EID 1: cmd.exe process creation with the full LDIFDE command line
- The command attempts to export directory data to `C:\Windows\temp\atomic_ldifde.txt` using subtree scope

**Process Exit Telemetry**: Security EID 4689 shows cmd.exe exited with status 0x1 (failure), indicating the LDIFDE operation was unsuccessful

**PowerShell Activity**: Standard test framework boilerplate with Set-ExecutionPolicy bypass commands in EID 4103/4104 events

**Sysmon Coverage**: Process creation for both whoami.exe (EID 1) and cmd.exe (EID 1), process access events (EID 10), and image loads (EID 7) showing .NET runtime initialization

## What This Dataset Does Not Contain

The dataset lacks the actual LDIFDE process creation in Sysmon due to the include-mode filtering configuration that only captures known-suspicious patterns. LDIFDE.exe is not included in the LOLBins patterns, so its process creation is not captured in Sysmon events.

Notably absent is any file creation event for the target output file `C:\Windows\temp\atomic_ldifde.txt`, suggesting the LDIFDE operation failed before creating the output file. There are no network connection events to domain controllers, no LDAP-related authentication events, and no successful file I/O operations related to the directory export.

The dataset also lacks any Directory Service event logs that would show the actual LDAP queries being performed against Active Directory.

## Assessment

This dataset provides moderate value for detection engineering focused on process-level indicators but has significant limitations for comprehensive LDIFDE detection. The Security 4688 events with command-line logging provide the primary detection value, clearly showing the LDIFDE execution attempt with suspicious parameters.

The failure of the operation (exit code 0x1) limits the dataset's utility for understanding successful domain enumeration patterns, but it effectively demonstrates attempt-based detection opportunities. For building robust detections, this would be stronger with successful executions, network telemetry showing LDAP connections, and ideally Directory Service logs capturing the actual queries.

## Detection Opportunities Present in This Data

1. **LDIFDE Command Line Detection**: Security EID 4688 with command line `ldifde.exe -f * -p subtree` - monitor for LDIFDE executions with file output and subtree scope parameters

2. **Suspicious Output Location**: File output to `C:\Windows\temp\` directory indicates potential non-administrative usage of LDIFDE

3. **PowerShell-to-CMD-to-LDIFDE Chain**: Process ancestry showing PowerShell spawning cmd.exe with LDIFDE execution suggests scripted reconnaissance activity

4. **LDIFDE Parent Process Analysis**: LDIFDE spawned by non-administrative processes or from unexpected parent processes like PowerShell/cmd chains

5. **Failed Enumeration Attempts**: Monitor for LDIFDE processes with exit code 0x1 which may indicate unauthorized enumeration attempts being blocked by permissions

6. **Temporal Correlation**: LDIFDE execution in conjunction with other reconnaissance tools like whoami.exe within the same PowerShell session indicates broader discovery activity
