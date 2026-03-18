# T1087.002-6: Domain Account — Adfind - Enumerate Active Directory Admins

## Technique Context

T1087.002 Domain Account discovery involves adversaries enumerating domain user accounts to identify potential targets for lateral movement, privilege escalation, or data exfiltration. This technique is fundamental to most Active Directory-based attack chains. AdFind is a popular command-line Active Directory query tool often used by both administrators and attackers for enumeration tasks. The specific `-sc admincountdmp` parameter targets accounts with the adminCount attribute set to 1, which identifies privileged accounts including Domain Admins, Enterprise Admins, and other highly privileged groups. Detection communities focus on monitoring for suspicious LDAP queries, unusual process executions from administrative tools, and patterns of account enumeration that deviate from normal administrative activity.

## What This Dataset Contains

This dataset captures a failed AdFind execution attempting to enumerate privileged domain accounts. The key artifacts include:

**Process Creation Chain**: Security event 4688 shows the process chain: `powershell.exe` → `cmd.exe` with command line `"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\AdFind.exe" -sc admincountdmp`. The cmd.exe process exits with status 0x1, indicating failure.

**Sysmon Process Events**: Event ID 1 captures both the whoami.exe execution (`"C:\Windows\system32\whoami.exe"`) and cmd.exe creation with the full AdFind command line. Notably, there's no Sysmon ProcessCreate event for AdFind.exe itself, suggesting it didn't execute successfully.

**Process Access Monitoring**: Sysmon event ID 10 shows PowerShell accessing both whoami.exe and cmd.exe processes with full access rights (0x1FFFFF), indicating normal parent-child process relationships.

**PowerShell Telemetry**: The PowerShell channel contains only framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) with no substantive script content related to the AdFind execution.

## What This Dataset Does Not Contain

**AdFind Execution**: There are no events showing AdFind.exe actually running - no Sysmon ProcessCreate, Security 4688, or any network connections that would indicate successful LDAP queries to domain controllers.

**LDAP Query Telemetry**: No network events, DNS queries for domain controllers, or authentication events that would accompany successful Active Directory enumeration.

**AdFind Output**: No file creation events for output files that AdFind would typically generate when dumping account information.

**Error Details**: While cmd.exe exits with code 0x1, there are no specific error messages explaining why AdFind failed to execute (likely due to the tool not being present at the specified path).

## Assessment

This dataset has limited utility for building detections around successful AdFind enumeration since the tool never actually executed. However, it provides valuable examples of the process creation patterns and command-line artifacts that precede AdFind usage. The Security 4688 events with command-line logging capture the full attack intent, making this dataset useful for detecting AdFind deployment attempts even when execution fails. The clear process lineage from PowerShell through cmd.exe to the intended AdFind execution represents a common attack pattern. For comprehensive AdFind detection development, additional datasets showing successful execution with LDAP traffic and domain controller interactions would be necessary.

## Detection Opportunities Present in This Data

1. **Command Line Detection**: Monitor Security 4688 events for command lines containing "AdFind.exe" combined with AD enumeration parameters like "-sc admincountdmp", "-default -f objectClass=user", or similar LDAP query patterns.

2. **Process Chain Analysis**: Detect PowerShell spawning cmd.exe that immediately executes external tools from non-standard directories (e.g., paths containing "atomics", "tools", or "ExternalPayloads").

3. **AdFind Binary Detection**: Alert on any process creation attempts for "adfind.exe" regardless of success, as this tool is rarely used in legitimate environments outside of specific administrative contexts.

4. **Privileged Account Enumeration**: Monitor for command lines containing "admincount", "adminCountdmp", or other parameters specifically targeting high-privilege account discovery.

5. **Tool Staging Detection**: Watch for file creation or execution attempts in common penetration testing tool directories that match known tool repositories or frameworks.

6. **Administrative Tool Abuse**: Correlate executions of administrative tools like AdFind with user context - flag when executed by non-administrative users or from suspicious parent processes.
