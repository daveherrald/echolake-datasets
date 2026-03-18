# T1033-6: System Owner/User Discovery — System Discovery - SocGholish whoami

## Technique Context

T1033 System Owner/User Discovery is a fundamental Discovery technique where adversaries enumerate the current user context and system privileges. This test replicates a behavioral pattern attributed to SocGholish, a JavaScript-based malware framework that has been deployed extensively in drive-by download campaigns. SocGholish commonly executes `whoami /all` early in its execution chain to enumerate the current user, their group memberships, and token privileges — information that determines whether the malware proceeds with credential theft, lateral movement, or simply reports back to C2.

The test implements a randomization wrapper: it generates a random 5-character alphanumeric string, constructs a filename like `rad<random>.tmp` in `$env:temp`, and redirects `whoami.exe /all` output to that file. This file name randomization mimics evasion techniques used by malware to avoid static filename-based detections on output artifacts. The cleanup step uses a wildcard glob (`Remove-Item $env:temp\rad*.tmp`) to clean up any matching files.

Detection of `whoami.exe` is well-established via process creation logging, but the SocGholish-style obfuscation — wrapping in a PowerShell random-filename generator — adds complexity for defenders who rely on static file path detections rather than the process execution itself.

## What This Dataset Contains

This dataset contains 137 events: 100 PowerShell events, 5 Security events, and 32 Sysmon events.

The Security channel (EID 4688) captures the full attack chain. The main execution shows a PowerShell invocation containing the random filename generation logic and `whoami.exe /all >> $env:temp\$file` redirection — the full command line is preserved with the string generation code intact. A discrete EID 4688 for `whoami.exe /all` appears as a separate process creation event. The cleanup EID 4688 shows `Remove-Item -Path $env:temp\rad*.tmp -Force`. Two `whoami.exe` launches without `/all` appear as test framework verification.

Notably, this dataset contains one more Security 4688 event than the defended dataset (5 vs. 12 total in defended — that difference is largely from Defender's own process creations). The core execution process chain is the same in both.

Sysmon EID 1 captures `whoami.exe` with `RuleName: technique_id=T1033,technique_name=System Owner/User Discovery`, and the child PowerShell with the full randomization script block tagged `technique_id=T1059.001`. EID 10 shows `powershell.exe` accessing `whoami.exe` memory. Two EID 11 file creation events from `svchost.exe` appear — these are unrelated Windows service activity coinciding with the test window, not technique artifacts. EID 7 image loads include `urlmon.dll` into PowerShell (network-capable initialization artifact).

The Sysmon EID 11 events from `svchost.exe` tagged `technique_id=T1574.010` (Services File Permissions Weakness) are background activity from Windows Update or similar services writing to service-accessible paths — they are not related to the SocGholish simulation.

Compared to the defended dataset (31 Sysmon, 12 Security, 41 PowerShell), the undefended version has very similar event counts, consistent with the fact that `whoami.exe` execution is not blocked by Defender. The primary difference is in the PowerShell channel's volume.

## What This Dataset Does Not Contain

The actual contents of the `rad*.tmp` output file are not captured — no file creation Sysmon EID 11 appears for the temp file, likely because the Sysmon configuration filters `.tmp` extensions or non-suspicious paths in `$env:temp`. The random filename generated at runtime is not observable without direct file system access or a broader file creation audit policy.

No network events are present. No DNS resolution or external connectivity appears. The LDAP or domain-level enumeration that `whoami /all` surfaces (group memberships, SIDs) is visible only in the output file, not in Windows event telemetry directly.

## Assessment

This is a clean, concise dataset demonstrating `whoami /all` discovery wrapped in a SocGholish-style PowerShell randomization pattern. The Security 4688 channel provides the strongest detection signal — both the wrapper script (with full command line) and the discrete `whoami.exe /all` process creation are captured. The dataset is well-suited for building detections that look for `whoami /all` with output redirection to temp files, particularly when wrapped in PowerShell random-filename generation.

## Detection Opportunities Present in This Data

1. EID 4688 for `whoami.exe` with the `/all` argument is a high-fidelity indicator — the `/all` flag requests full privilege and group membership output and is far less common in legitimate administrative activity than bare `whoami`.

2. EID 4688 for `powershell.exe` containing `whoami.exe /all` with stdout redirection (`>>`) to a temp file, especially using a randomized filename pattern generated at runtime, matches SocGholish's specific evasion approach.

3. Sysmon EID 1 for `whoami.exe` launched from `powershell.exe` with `RuleName: technique_id=T1033` provides a Sysmon-native detection anchor.

4. The pattern of PowerShell generating random filenames using `Get-Random` on character arrays combined with `whoami` or other discovery utilities is a behavioral indicator worth building a detection around — legitimate scripts rarely combine random filename generation with native enumeration tools.

5. EID 4688 for `powershell.exe` containing `Remove-Item` with a wildcard glob targeting temp files matching a known discovery output pattern (e.g., `rad*.tmp`) can indicate post-execution cleanup behavior.
