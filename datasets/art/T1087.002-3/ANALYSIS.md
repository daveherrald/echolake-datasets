# T1087.002-3: Domain Account — Enumerate logged on users via CMD (Domain)

## Technique Context

T1087.002 Domain Account Discovery is a fundamental reconnaissance technique where adversaries enumerate domain user accounts to understand the environment's user base and identify high-value targets. This specific test demonstrates a common approach: using the built-in `query user` command to enumerate currently logged-on users on a domain system. Attackers frequently use this technique during lateral movement phases to identify active user sessions, particularly targeting administrative accounts or users with elevated privileges. The detection community typically focuses on monitoring unusual process executions of enumeration utilities like `query.exe`, `quser.exe`, and related commands, especially when executed in rapid succession or from unusual parent processes.

## What This Dataset Contains

This dataset captures a complete execution of domain user enumeration using the Windows `query user` command. The technique executes through PowerShell with the command line `"cmd.exe" /c query user /SERVER:%COMPUTERNAME%`, which resolves to `query user /SERVER:ACME-WS02`.

**Security Event 4688 shows the process chain:**
- PowerShell (PID 30496) spawns cmd.exe with command line `"cmd.exe" /c query user /SERVER:%COMPUTERNAME%`
- cmd.exe (PID 30532) spawns query.exe with command line `query user /SERVER:ACME-WS02`
- query.exe (PID 31008) spawns quser.exe with command line `"C:\Windows\system32\quser.exe" /SERVER:ACME-WS02`

**Sysmon provides detailed process creation events:**
- EID 1 captures the complete process chain with parent-child relationships
- ProcessGuid tracking shows the lineage: PowerShell → cmd.exe → query.exe → quser.exe
- Command lines are fully preserved, including the SERVER parameter specifying the local machine

**Process exit events in Security 4689 show the execution completed:**
- quser.exe exits with status 0x1 (indicating no logged-on users found)
- query.exe exits with status 0x1 
- cmd.exe exits with status 0x1

The PowerShell channel contains only test framework boilerplate (`Set-StrictMode` and `Set-ExecutionPolicy Bypass` events).

## What This Dataset Does Not Contain

This dataset lacks several elements that would make it more representative of real-world scenarios. Most notably, there are no logged-on users on this test system, so quser.exe exits with error status 0x1 rather than returning actual user enumeration data. In production environments, successful execution would typically show interactive users, RDP sessions, or service accounts.

The dataset doesn't include network-related telemetry that might occur if the query targeted remote systems, nor does it capture any output redirection or file operations that attackers might use to store enumeration results. Additionally, there's no evidence of follow-on reconnaissance activities that would typically accompany user enumeration in real attack scenarios.

## Assessment

This dataset provides excellent telemetry for detecting domain user enumeration attempts. The Security and Sysmon channels capture comprehensive process execution data with complete command lines and parent-child relationships. The process chain from PowerShell through cmd.exe to query.exe and quser.exe is clearly visible and would be easily detectable through standard process monitoring rules.

The combination of Security 4688 events (providing broad coverage) and Sysmon EID 1 events (providing detailed metadata and parent process tracking) creates robust detection opportunities. However, the dataset would be stronger if it included scenarios with actual logged-on users to show successful enumeration output, as well as variations targeting remote systems.

## Detection Opportunities Present in This Data

1. **Process creation monitoring for query.exe with user enumeration arguments** - Security 4688 and Sysmon EID 1 show query.exe execution with command line `query user /SERVER:ACME-WS02`

2. **Process creation monitoring for quser.exe execution** - Both event sources capture quser.exe spawning with SERVER parameter, indicating remote/explicit user enumeration

3. **Process chain analysis detecting PowerShell→cmd→query→quser execution sequence** - Sysmon ProcessGuid tracking enables correlation of the complete attack chain

4. **Command line analysis for user enumeration patterns** - Multiple command lines contain "query user" and "/SERVER:" parameters indicating systematic user discovery

5. **Abnormal parent process detection for enumeration utilities** - cmd.exe spawned by PowerShell executing user enumeration commands represents suspicious activity

6. **Process clustering detection for rapid enumeration tool execution** - Sequential execution of query.exe and quser.exe within seconds indicates automated reconnaissance

7. **Exit code analysis for failed enumeration attempts** - Security 4689 events show exit status 0x1 for enumeration tools, potentially indicating defensive measures or empty environments
