# T1083-5: File and Directory Discovery — Simulating MAZE Directory Enumeration

## Technique Context

T1083 (File and Directory Discovery) covers adversary enumeration of filesystem contents to understand the environment, locate valuable data, and plan staging or exfiltration. The MAZE ransomware gang became notorious not only for encrypting data but for systematically enumerating files before encryption to identify high-value targets for their double-extortion model. MAZE's directory enumeration pattern — recursively walking user-specific directories like Desktop, Downloads, Documents, and AppData subdirectories, plus Program Files and the system drive root — became a behavioral signature of their pre-encryption reconnaissance phase.

This test replicates MAZE's directory enumeration logic using PowerShell's `Get-ChildItem` cmdlet, writing results to a staging file in `C:\Windows\TEMP\`. This differs from simple `dir` commands in that it systematically iterates a predefined list of high-value locations, writes accumulated output to a file, and does so recursively — the behavioral signature of pre-exfiltration data mapping rather than casual file browsing.

Defender does not block this technique; both defended and undefended datasets contain the same technique-relevant telemetry. The differences in event counts reflect varying levels of system activity during capture.

## What This Dataset Contains

This dataset covers a 4-second window (2026-03-14T23:33:26Z–23:33:30Z).

**Process execution chain**: Sysmon EID 1 records `whoami.exe` (PID 2284) at 23:33:27 as a pre-execution identity check, then the main PowerShell process (PID 5284) at 23:33:28 with the explicit enumeration command line:

```
"powershell.exe" & {$folderarray = @("Desktop", "Downloads", "Documents", "AppData/Local", "AppData/Roaming")
Get-ChildItem -Path $env:homedrive -ErrorAction SilentlyContinue | Out-File -append $env:temp\T1083Test5.txt
Get-ChildItem -Path $env:programfiles -erroraction silentlycontinue | Out-File -append $...
```

Sysmon tags this with `technique_id=T1083,technique_name=File and Directory Discovery`. The process runs as `NT AUTHORITY\SYSTEM` from `C:\Windows\TEMP\`.

A second PowerShell process (PID 2384) appears later in the Security channel at 23:33:29, consistent with the test framework spawning a cleanup subprocess.

**Security events**: Four EID 4688 events capture `whoami.exe`, the enumeration `powershell.exe`, a second `whoami.exe`, and a second `powershell.exe` for cleanup. All run as SYSTEM.

**PowerShell script block logging**: 96 EID 4104 events and 15 EID 4103 events were captured (111 total). The EID 4103 module pipeline events are significant — they capture the actual `Get-ChildItem` executions with specific paths. The defended analysis of the matched dataset reported EID 4103 content showing paths like `C:\Program Files`, `C:\Users\mm11711\AppData\Local`, and machine account directories being enumerated. The 15 EID 4103 events here represent each `Get-ChildItem` invocation in the enumeration loop.

**DLL loading**: 22 Sysmon EID 7 events reflect .NET and PowerShell runtime. The higher count compared to simple command-line tests reflects `Get-ChildItem`'s use of additional .NET filesystem APIs.

**Process access**: Four Sysmon EID 10 events show test framework parent-child process access patterns.

**Named pipe**: Two Sysmon EID 17 events record PowerShell host pipes for the two PowerShell instances.

Comparing to the defended dataset (29 sysmon, 17 security, 56 powershell): the undefended run has more sysmon events (34 vs 29) and more powershell events (111 vs 56), while security events decreased dramatically (4 vs 17). The security event drop suggests the defended run captured additional process creation events from Defender activity; the powershell event increase reflects the longer execution in the undefended case. The `Out-File` operation writes to disk, so some events in both datasets reflect file system access.

## What This Dataset Does Not Contain

The contents of `C:\Windows\TEMP\T1083Test5.txt` — the actual file listing produced by the enumeration — do not appear in any event log. The file was created (the `Out-File -append` calls executed), but Sysmon EID 11 file creation events for `T1083Test5.txt` do not appear in the available 20-sample set for this dataset. The enumeration results are in the file on disk, not in the telemetry.

There are no events revealing which specific files or paths were discovered — only that the enumeration commands were issued against known target directories.

## Assessment

This dataset provides a complete behavioral record of MAZE-pattern directory enumeration. The command line in Sysmon EID 1 and Security EID 4688 shows exactly what directories were targeted (`$env:homedrive`, `$env:programfiles`, user subdirectories from `$folderarray`) and the output staging file path (`$env:temp\T1083Test5.txt`). The 15 EID 4103 module pipeline events contain the per-directory enumeration detail.

The `T1083Test5.txt` filename is an ART test framework artifact — a real MAZE operator would use a less identifiable output file path, or pipe output to an in-memory structure. This is one of the cleaner, more complete datasets in the undefended collection for T1083.

## Detection Opportunities Present in This Data

**Sysmon EID 1 / Security EID 4688**: The command line explicitly names high-value user directories in a `$folderarray`, the `Get-ChildItem` pattern, and `Out-File -append $env:temp\T1083Test5.txt`. The staging file path in `%TEMP%` with a test-numbered filename is an obvious indicator in this ART context, but the underlying pattern — PowerShell recursively enumerating user directories and writing to a staging file — is the detection target.

**PowerShell EID 4103**: Module pipeline events for each `Get-ChildItem` invocation provide per-path visibility. Fifteen consecutive `Get-ChildItem` operations across Desktop, Downloads, Documents, and AppData subdirectories within seconds, all as SYSTEM, is a reliable behavioral indicator.

**Sysmon EID 11 (File Created)**: `T1083Test5.txt` creation in `C:\Windows\TEMP\` by a SYSTEM-privilege PowerShell process signals data staging. The file naming convention in this test is ART-specific, but file creation during rapid directory enumeration is a reliable pattern.

**Behavioral timing**: The enumeration runs at 23:33:28, 16 seconds after hostname discovery and 9 seconds before DirLister (T1083-6). The temporal compression of multiple discovery techniques is a strong composite indicator.
