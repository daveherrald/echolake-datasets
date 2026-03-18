# T1033-7: System Owner/User Discovery — System Owner/User Discovery Using Command Prompt

## Technique Context

T1033 System Owner/User Discovery is a fundamental Discovery technique where adversaries enumerate users and sessions on a compromised system. This test demonstrates enumeration through the Windows Command Prompt using a chained sequence of built-in utilities: `%USERNAME%`, `%USERDOMAIN%`, `net users`, and `query user`. This multi-command approach reflects realistic adversary behavior, as combining these tools provides a more complete picture of the authentication state than any single command alone — local account list from `net users`, active interactive sessions from `query user` (which calls `quser.exe`), and the current executing user from environment variables.

The test writes discovery output to a randomized temp file (`user_info_%random%.tmp`) and cleans it up afterward, following the same collect-and-clean pattern common across discovery-phase tradecraft. Using `%random%` at the CMD level provides a simpler randomization than the PowerShell equivalent in T1033-6, but serves the same purpose of evading static temp-file path detections.

Detection of this technique is well-supported by Windows process creation logging. The child process chain — `cmd.exe` → `net.exe` → `net1.exe`, and `cmd.exe` → `query.exe` → `quser.exe` — produces distinct EID 4688 entries that are easy to correlate. The presence of `quser.exe` in particular is unusual outside of system administration contexts.

## What This Dataset Contains

This dataset contains 131 events: 106 PowerShell events, 8 Security events, and 17 Sysmon events.

The Security channel (EID 4688) provides the richest evidence and is worth examining in detail. The attack launches via PowerShell spawning `cmd.exe` with the full compound command: `cmd.exe /c set file=$env:temp\user_info_%random%.tmp & echo Username: %USERNAME% > %file% & echo User Domain: %USERDOMAIN% >> %file% & net users >> %file% & query user >> %file%`. This single command line captures the entire discovery operation. Subsequent discrete EID 4688 entries record each tool in the chain: `net.exe` (with `users` argument), `net1.exe` (the internal implementation called by `net.exe`), `query.exe` (with `user` argument), and `quser.exe` (the actual logged-on user query executable). A cleanup EID 4688 shows `cmd.exe /c del $env:temp\user_info_*.tmp`.

Compared to the defended dataset (21 Sysmon, 18 Security, 34 PowerShell), the undefended version has fewer Security events (8 vs. 18) and fewer Sysmon events (17 vs. 21). This initially appears counterintuitive, but reflects that Defender in the defended case generates its own process creations and memory access events when examining the `net.exe`/`quser.exe` chain. With Defender disabled, the execution is cleaner.

Sysmon EID 1 records `cmd.exe` launching with the full compound command, tagged `technique_id=T1087.001,technique_name=Local Account`. EID 10 (process access) shows PowerShell accessing `whoami.exe` and `cmd.exe`. EID 11 (file create) in `sysmon` captures a temp directory write from `cmd.exe`, tagged `technique_id=T1574.010` — this is the `user_info_*.tmp` output file. EID 7 image loads again show PowerShell loading `urlmon.dll`.

The Sysmon configuration captures `cmd.exe` via a LOLBin include rule, so `cmd.exe` spawned from PowerShell is visible even though the Sysmon config uses include-mode process creation filtering. The `net.exe`, `net1.exe`, `query.exe`, and `quser.exe` child processes appear only in Security EID 4688, not Sysmon EID 1, because they fall outside the Sysmon include rules.

## What This Dataset Does Not Contain

The `query.exe` → `quser.exe` process chain and `net.exe` → `net1.exe` chain are visible in Security EID 4688 but not in Sysmon EID 1. This is a direct consequence of the Sysmon include-mode configuration, which only captures processes matching known-suspicious patterns like LOLBins.

The contents of the temp file are not captured. No file creation Sysmon EID 11 events appear for the temp file itself in the samples. The cleanup `del` command does not trigger a file deletion event in this dataset.

No domain-level events (Kerberos, LDAP) appear, as all enumeration is local (`net users` returns local accounts, `query user` returns local sessions).

## Assessment

This is a highly valuable dataset for detection engineering focused on multi-stage Windows user discovery using native CMD tools. The Security 4688 chain of `cmd.exe` → `net.exe` → `net1.exe` → `query.exe` → `quser.exe` is well-documented in threat intelligence and provides a multi-hop process ancestry detection opportunity. The full compound command line in the initial `cmd.exe` spawn is the single highest-fidelity indicator. This dataset also clearly illustrates the `net.exe`/`net1.exe` parent-child relationship that defenders should include in detection logic.

## Detection Opportunities Present in This Data

1. EID 4688 for `cmd.exe` with a command line containing both `net users` and `query user` in the same invocation is a strong composite indicator of user enumeration with output redirection to temp files.

2. EID 4688 for `query.exe` with the `user` argument is unusual in non-administrative workstation contexts and reliably indicates session enumeration — especially significant when `query.exe` is spawned by `cmd.exe` which was itself launched by `powershell.exe`.

3. EID 4688 for `quser.exe` spawned by `query.exe` provides a secondary anchor; `quser.exe` is rarely seen in normal workstation operation.

4. EID 4688 for `net1.exe` as a child of `net.exe` with `users` argument, spawned by `cmd.exe` from `powershell.exe`, creates a four-process chain that is a reliable indicator of programmatic local account enumeration.

5. Sysmon EID 1 for `cmd.exe` spawned by `powershell.exe` with a command line containing `%USERNAME%`, `%USERDOMAIN%`, or `%random%` combined with redirection to a temp file path is a behavioral signature matching this technique.

6. The pattern of `cmd.exe /c del` targeting a wildcard temp path (`user_info_*.tmp`) immediately following a discovery command sequence can indicate automated collect-and-clean behavior.
