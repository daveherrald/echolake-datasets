# T1018-10: Remote System Discovery — Adfind - Enumerate Active Directory Computer Objects

## Technique Context

T1018 Remote System Discovery encompasses techniques adversaries use to identify remote systems within a network environment. AdFind is a legitimate Active Directory query tool frequently abused by threat actors for reconnaissance activities, particularly in ransomware and APT operations. The tool's ability to enumerate AD objects, including computer accounts, makes it valuable for lateral movement planning and understanding network topology.

The detection community focuses heavily on AdFind usage due to its prevalence in high-profile attacks. Key detection opportunities include monitoring for the AdFind executable itself, characteristic command-line patterns (especially LDAP filters), and the tool's typical deployment from staging directories. AdFind is often deployed as part of automated reconnaissance scripts that query multiple AD object types in succession.

## What This Dataset Contains

This dataset captures a straightforward AdFind execution targeting computer objects in Active Directory. The key telemetry shows:

**Process Creation Chain**: Security event 4688 shows cmd.exe (PID 7368) executing `"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\AdFind.exe" -f (objectcategory=computer)` spawned from powershell.exe (PID 5492). The full command line reveals the LDAP filter `(objectcategory=computer)` designed to enumerate AD computer objects.

**Sysmon Process Creation**: Sysmon EID 1 captures both whoami.exe execution for initial system discovery (`"C:\Windows\system32\whoami.exe"`) and the cmd.exe process with the complete AdFind command line. The whoami execution appears to be reconnaissance preceding the main AdFind query.

**Process Access Events**: Sysmon EID 10 shows PowerShell accessing both whoami.exe and cmd.exe processes with full access rights (0x1FFFFF), indicating process monitoring or interaction during execution.

**Exit Status**: Security 4689 events show cmd.exe exiting with status 0x1, suggesting the AdFind execution may have encountered an error or been interrupted.

## What This Dataset Does Not Contain

Notably missing from this dataset is any Sysmon ProcessCreate event for AdFind.exe itself, despite the command line clearly showing its execution path. This absence occurs because the sysmon-modular configuration uses include-mode filtering for ProcessCreate events, and AdFind.exe doesn't match the predefined suspicious process patterns. This represents a significant detection gap - while we can see the command line in the cmd.exe execution, we lose visibility into AdFind's actual process behavior, child processes, or network connections.

The dataset also lacks any network activity telemetry that would typically accompany successful AD queries, and there are no DNS resolution events that might indicate LDAP queries to domain controllers. The cmd.exe exit code of 0x1 suggests the AdFind execution may not have completed successfully.

## Assessment

This dataset provides moderate utility for detection engineering focused on AdFind reconnaissance activities. The Security channel's command-line logging captures the critical detection artifact - the full AdFind command with LDAP filter - which is often sufficient for alerting purposes. However, the missing Sysmon ProcessCreate event for AdFind.exe itself creates blind spots in process-based detections and behavioral analysis.

The dataset effectively demonstrates the importance of command-line auditing for detecting reconnaissance tools, as the parent process telemetry provides the essential context even when the target executable isn't directly monitored. For detection engineers, this highlights the value of comprehensive command-line logging as a backstop when Sysmon filtering might miss specific tools.

## Detection Opportunities Present in This Data

1. **AdFind Command Line Pattern**: Security 4688 command line contains `AdFind.exe` with LDAP filter `(objectcategory=computer)` - classic reconnaissance signature
2. **AdFind Executable Path**: Process execution from staging directory `C:\AtomicRedTeam\atomics\..\ExternalPayloads\AdFind.exe` indicates potential threat actor tool deployment
3. **LDAP Filter Enumeration**: Command line filter `(objectcategory=computer)` specifically targets AD computer object enumeration
4. **Reconnaissance Process Chain**: whoami.exe execution followed immediately by AdFind suggests systematic reconnaissance methodology
5. **PowerShell-to-CMD-to-AdFind Chain**: Multi-stage process execution pattern (powershell.exe → cmd.exe → AdFind.exe) common in scripted reconnaissance
6. **System-Level AD Queries**: Execution under SYSTEM context performing AD enumeration may indicate compromise or malicious automation
7. **Staging Directory Usage**: Tool execution from ExternalPayloads directory suggests non-standard software deployment consistent with attack toolkits
