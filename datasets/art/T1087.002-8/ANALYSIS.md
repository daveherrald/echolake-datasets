# T1087.002-8: Domain Account — Adfind - Enumerate Active Directory Exchange AD Objects

## Technique Context

T1087.002 (Domain Account) represents adversary attempts to enumerate domain user accounts within Active Directory environments. This technique is fundamental to reconnaissance phases of attacks, allowing threat actors to map out potential targets, understand organizational structure, and identify high-value accounts. AdFind is a legitimate command-line LDAP query tool commonly abused by attackers for Active Directory enumeration due to its powerful querying capabilities and relative stealth compared to other reconnaissance methods. The detection community focuses heavily on monitoring for unusual LDAP queries, especially those targeting sensitive AD objects like Exchange-related configurations, as these often precede lateral movement or privilege escalation attempts.

## What This Dataset Contains

This dataset captures a PowerShell-initiated execution of AdFind targeting Exchange addresses within Active Directory. The Security event logs show the complete process chain: PowerShell (PID 35128) spawning cmd.exe (PID 26428) with the command line `"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\AdFind.exe" -sc exchaddresses`. The Security 4688 event clearly documents this suspicious command execution with full command-line visibility. Sysmon provides complementary telemetry with ProcessCreate events for both whoami.exe (EID 1, rule matching T1033 System Owner/User Discovery) and cmd.exe (EID 1, rule matching T1059.003 Windows Command Shell). Process access events (Sysmon EID 10) show PowerShell accessing both spawned processes with full access rights (0x1FFFFF). The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass scriptblocks and CommandInvocation events).

## What This Dataset Does Not Contain

Notably absent is any ProcessCreate event for AdFind.exe itself, despite the command line clearly showing its execution path. This indicates the AdFind execution was blocked, likely by Windows Defender's real-time protection. The cmd.exe process exits with status 0x1 (failure), confirming the AdFind execution was prevented. There are no network connections, LDAP queries, or file operations related to actual AD enumeration, as the technique was blocked before completion. The dataset lacks any evidence of successful AD object enumeration or Exchange address discovery that the technique was designed to perform.

## Assessment

This dataset provides excellent telemetry for detecting *attempted* AdFind execution but limited value for understanding successful AD enumeration behavior. The Security 4688 events with command-line logging are the primary detection value, clearly showing the suspicious AdFind invocation with Exchange-specific parameters. Sysmon's ProcessCreate filtering means the actual AdFind process wasn't captured, but the cmd.exe wrapper provides sufficient evidence. The process access events add context about PowerShell's interaction with spawned processes. While the technique didn't succeed, the attempt telemetry is valuable for detection engineering focused on identifying reconnaissance attempts before they complete.

## Detection Opportunities Present in This Data

1. **AdFind Command Line Detection** - Security 4688 events showing cmd.exe or PowerShell executing processes from ExternalPayloads directory with AdFind.exe and specific LDAP query parameters like "-sc exchaddresses"

2. **Suspicious Process Chain Analysis** - PowerShell spawning cmd.exe with external tool execution paths, particularly targeting legitimate AD query tools in non-standard locations

3. **Exchange-Specific AD Enumeration** - Command lines containing Exchange-related LDAP search criteria ("exchaddresses", "exchange", "mail") combined with known reconnaissance tools

4. **Failed Process Execution Patterns** - cmd.exe processes exiting with error codes (0x1) immediately after attempting to execute reconnaissance tools from suspicious paths

5. **PowerShell Process Access Monitoring** - Sysmon EID 10 events showing PowerShell processes accessing cmd.exe children with full access rights during reconnaissance tool execution attempts

6. **Reconnaissance Tool Path Detection** - Process creation events referencing known penetration testing framework paths (AtomicRedTeam, ExternalPayloads) combined with legitimate AD query utilities
