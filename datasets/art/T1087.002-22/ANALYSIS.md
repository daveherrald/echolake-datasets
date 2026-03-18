# T1087.002-22: Domain Account — Suspicious LAPS Attributes Query with adfind ms-Mcs-AdmPwd

## Technique Context

T1087.002 (Account Discovery: Domain Account) involves adversaries attempting to get a listing of domain accounts, which can be used for situational awareness and discovery of accounts for later exploitation. This specific test focuses on querying Microsoft Local Administrator Password Solution (LAPS) attributes through Active Directory, which is a particularly high-value discovery technique. LAPS stores local administrator passwords centrally in Active Directory, making these attributes (`ms-Mcs-AdmPwd` and `ms-Mcs-AdmPwdExpirationTime`) prime targets for attackers seeking privileged access.

The detection community focuses heavily on monitoring for LDAP queries that specifically target LAPS attributes, as legitimate administrative access to these fields is typically rare and highly controlled. Third-party tools like AdFind performing these queries are especially suspicious, as they indicate potential reconnaissance or credential harvesting attempts.

## What This Dataset Contains

The dataset captures a PowerShell-executed AdFind query targeting LAPS attributes. Key telemetry includes:

**Security Event 4688**: PowerShell process creation with the complete command line: `"powershell.exe" & {& \"C:\AtomicRedTeam\atomics\..\ExternalPayloads\AdFind.exe\"  -h $env:USERDOMAIN -s subtree -f \"objectclass=computer\" ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime}`

**Sysmon Event 1**: Process creation for both the initial PowerShell process (PID 35932) and the whoami.exe execution (PID 12220) used for environment discovery

**PowerShell Event 4104**: Script block logging captures the execution of the AdFind command: `& "C:\AtomicRedTeam\atomics\..\ExternalPayloads\AdFind.exe" -h $env:USERDOMAIN -s subtree -f "objectclass=computer" ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime`

**Sysmon Event 10**: Process access events showing PowerShell accessing both the whoami.exe and subsequent PowerShell processes with full access rights (0x1FFFFF)

The command specifically queries all computer objects in the domain (`objectclass=computer`) for the LAPS password (`ms-Mcs-AdmPwd`) and expiration time (`ms-Mcs-AdmPwdExpirationTime`) attributes.

## What This Dataset Does Not Contain

The dataset lacks the actual AdFind.exe process creation event, likely because the sysmon-modular configuration's include-mode filtering for ProcessCreate events doesn't capture third-party administrative tools. There are no network events showing the LDAP queries to domain controllers, no DNS resolution events for domain controller lookups, and no authentication events that would typically accompany domain queries.

Notably absent are any Defender detection events or blocking notifications, suggesting the technique executed successfully without endpoint protection interference. The dataset also doesn't contain the actual query results or any file creation events showing output being written to disk.

## Assessment

This dataset provides excellent telemetry for detecting LAPS attribute queries through command-line analysis. The Security 4688 events with full command-line logging capture the complete attack vector, while PowerShell script block logging provides additional detection opportunities. The Sysmon process creation and access events offer supplementary context about the execution chain.

The primary detection value lies in the command-line arguments containing the specific LAPS attributes (`ms-Mcs-AdmPwd`, `ms-Mcs-AdmPwdExpirationTime`) combined with the use of third-party tools like AdFind. However, the dataset would be stronger with network telemetry showing the actual LDAP queries and authentication events demonstrating the domain interaction.

## Detection Opportunities Present in This Data

1. **Command-line detection for LAPS attribute queries** - Security 4688 and Sysmon 1 events containing "ms-Mcs-AdmPwd" or "ms-Mcs-AdmPwdExpirationTime" in process command lines

2. **PowerShell script block analysis** - PowerShell 4104 events executing AdFind with LAPS-specific attribute queries

3. **Third-party AD tool usage** - Process creation events showing AdFind.exe execution, particularly when combined with LDAP query parameters

4. **Suspicious process access patterns** - Sysmon 10 events showing PowerShell accessing multiple child processes with full access rights during discovery activities

5. **Environment discovery correlation** - Sequential execution of whoami.exe followed by domain queries, indicating reconnaissance workflow

6. **PowerShell execution policy bypass** - PowerShell 4103 events showing execution policy set to "Bypass" preceding suspicious domain queries
