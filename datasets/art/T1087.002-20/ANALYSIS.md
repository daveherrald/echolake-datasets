# T1087.002-20: Domain Account — Suspicious LAPS Attributes Query with Get-ADComputer all properties and SearchScope

## Technique Context

T1087.002 (Account Discovery: Domain Account) involves adversaries enumerating domain accounts to understand the Active Directory environment and identify potential targets. This specific test simulates a suspicious LAPS (Local Administrator Password Solution) attributes query using PowerShell's `Get-ADComputer` cmdlet with broad search parameters. LAPS stores local administrator passwords in Active Directory attributes, making these queries particularly valuable for attackers seeking privileged access credentials. The detection community focuses on identifying overly broad AD queries, especially those targeting LAPS attributes or using wildcards that could indicate reconnaissance activities rather than legitimate administrative tasks.

## What This Dataset Contains

This dataset captures the execution of `Get-ADComputer -SearchScope subtree -filter "name -like '*'" -Properties *`, which queries all computer objects in the domain with all properties. The telemetry shows:

**PowerShell Execution**: Security event 4688 captures the spawned PowerShell process with command line `"powershell.exe" & {Get-adcomputer -SearchScope subtree -filter \"name -like '*'\" -Properties *}`. PowerShell script block logging (EID 4104) records the actual cmdlet execution: `Get-adcomputer -SearchScope subtree -filter "name -like '*'" -Properties *`.

**Process Chain**: The execution flow shows a parent PowerShell process (PID 13444) spawning a child PowerShell process (PID 39992) specifically for this command. Sysmon EID 1 events capture both the `whoami.exe` execution for user context discovery and the PowerShell process creation.

**Image Loading**: Multiple Sysmon EID 7 events show the loading of .NET runtime components and PowerShell automation libraries, indicating PowerShell's initialization for AD module functionality.

**Windows Defender Integration**: The telemetry shows Defender's real-time protection DLLs (MpOAV.dll, MpClient.dll) being loaded into the PowerShell processes, but the technique executed successfully without blocking.

## What This Dataset Does Not Contain

The dataset lacks several key elements for complete AD enumeration analysis. There are no network connection events (Sysmon EID 3) showing the LDAP queries to domain controllers, likely due to the sysmon-modular configuration filtering these connections. No DNS resolution events appear for domain controller lookups. The PowerShell operational log contains mostly test framework boilerplate rather than detailed module loading or AD cmdlet execution details. Critically missing are any events showing the actual LDAP search results or data exfiltration, as the technique appears to have completed the query but the results aren't captured in the telemetry.

## Assessment

This dataset provides moderate utility for detecting broad AD enumeration attempts through PowerShell. The Security channel offers excellent command-line visibility showing the suspicious broad query parameters, while PowerShell script block logging captures the exact cmdlet usage. However, the absence of network telemetry significantly limits the ability to build comprehensive detections around AD communication patterns. The dataset is strongest for detecting the PowerShell execution patterns and command-line indicators, but weaker for understanding the network-level behavior and query results that would complete the attack chain.

## Detection Opportunities Present in This Data

1. **Broad AD Computer Queries**: Detect PowerShell executions containing `Get-ADComputer` with wildcard filters like `"name -like '*'"` and `-Properties *`, indicating reconnaissance attempts rather than targeted queries.

2. **LAPS-Related AD Enumeration**: Monitor for PowerShell commands querying all properties (`-Properties *`) from computer objects, which could expose LAPS password attributes.

3. **Subtree Scope AD Searches**: Alert on AD queries using `-SearchScope subtree` combined with broad filters, suggesting domain-wide enumeration activities.

4. **PowerShell Process Spawning for AD Operations**: Detect parent-child PowerShell process relationships where child processes execute AD-related cmdlets, potentially indicating scripted reconnaissance.

5. **Command-Line Pattern Matching**: Build detection rules targeting the specific command structure with escaped quotes and broad filter patterns typical of automated AD enumeration tools.

6. **Privilege Escalation Context**: Correlate broad AD queries with subsequent attempts to access privileged accounts or systems, as LAPS enumeration often precedes lateral movement attempts.
