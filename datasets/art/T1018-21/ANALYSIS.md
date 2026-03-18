# T1018-21: Remote System Discovery — Remote System Discovery - net group Domain Controller

## Technique Context

T1018 Remote System Discovery is a foundational reconnaissance technique where adversaries attempt to identify remote systems within a network environment. This specific test focuses on using the `net group` command to discover domain controllers — a critical asset enumeration technique commonly employed during the early stages of domain-focused attacks. Domain controllers are high-value targets containing sensitive authentication data, making their discovery a priority for attackers seeking to escalate privileges or establish persistence within Active Directory environments. The detection community focuses heavily on monitoring `net.exe` usage with domain-specific parameters, as this represents one of the most common and reliable methods for adversaries to map domain infrastructure from compromised endpoints.

## What This Dataset Contains

This dataset captures a clean execution of the `net group /domain "Domain controllers"` command through PowerShell. The key telemetry includes:

**Process creation chain in Security 4688 events:**
- PowerShell process (PID 6176) executing `powershell.exe`
- CMD spawned with command line `"cmd.exe" /c net group /domain "Domain controllers"`  
- Net.exe process with command line `net group /domain "Domain controllers"`
- Net1.exe process with command line `C:\Windows\system32\net1 group /domain "Domain controllers"`

**Sysmon ProcessCreate events (EID 1) show the same chain:**
- Whoami.exe execution (`"C:\Windows\system32\whoami.exe"`) for user discovery
- CMD.exe with the domain controller query command
- Net.exe and net1.exe with full command-line parameters preserved

**Process access events (Sysmon EID 10)** show PowerShell accessing both whoami.exe and cmd.exe with full access rights (0x1FFFFF), indicating process injection detection capabilities are active.

**PowerShell events contain only test framework boilerplate** — Set-StrictMode calls and Set-ExecutionPolicy Bypass invocations, with no script block content related to the actual technique execution.

## What This Dataset Does Not Contain

The dataset lacks the actual output of the `net group` command, as Windows event logs don't capture command output by default. There are no network connections logged to domain controllers, which would typically accompany successful domain queries. Sysmon DNS queries (EID 22) are absent, suggesting either the domain controller was resolved via cached entries or the DNS resolution wasn't captured by the current configuration. The PowerShell script block logging contains no evidence of the actual command being constructed or executed within PowerShell — the technique appears to have been invoked through PowerShell's Start-Process or similar mechanism rather than direct PowerShell cmdlets.

## Assessment

This dataset provides excellent coverage for detecting T1018 through process creation monitoring. The command-line logging in both Security 4688 and Sysmon EID 1 events clearly captures the distinctive `net group /domain` pattern that is highly specific to domain controller discovery activities. The process chain from PowerShell through CMD to net.exe and net1.exe is well-preserved and represents typical adversary behavior. However, the dataset would be stronger with network telemetry showing the actual LDAP queries to domain controllers, and PowerShell script block content showing how the command was initiated. The absence of command output also limits behavioral analysis opportunities.

## Detection Opportunities Present in This Data

1. **Net.exe domain controller enumeration** - Security 4688 and Sysmon EID 1 events with command line containing `net group /domain "Domain controllers"` or similar domain controller group queries

2. **Suspicious parent-child process relationships** - PowerShell spawning CMD.exe which spawns net.exe for domain queries, indicating potential living-off-the-land techniques

3. **Net.exe to net1.exe execution pattern** - The automatic invocation of net1.exe by net.exe provides a secondary detection point for the same technique

4. **Domain-specific net group queries** - Command lines containing `/domain` parameter combined with administrative group names like "Domain controllers", "Domain Admins", or "Enterprise Admins"

5. **Process access patterns** - Sysmon EID 10 showing PowerShell accessing spawned net.exe processes with full access rights, potentially indicating process injection or manipulation attempts

6. **Execution context analysis** - System-level execution of domain enumeration commands outside of typical administrative tools or scheduled tasks

7. **Command sequence correlation** - The rapid succession of whoami.exe followed by domain controller enumeration suggests reconnaissance activity escalation
