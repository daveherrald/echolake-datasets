# T1560.001-1: Archive via Utility — Compress Data for Exfiltration With Rar

## Technique Context

T1560.001 covers Archive via Utility, where adversaries use dedicated third-party archiving tools to compress collected data before exfiltration. Unlike the built-in PowerShell approach in T1560-1, this test stages an external binary: WinRAR's command-line interface (`Rar.exe`). WinRAR is one of the most common archiving tools found pre-installed on Windows systems worldwide, and its command-line interface has appeared in intrusions attributed to APT groups as well as financially motivated threat actors.

The specific command pattern — `rar a -r` — creates a recursive archive, and its use in incident investigations is well-documented. The presence of `Rar.exe` in a process tree under suspicious parents is a moderate-confidence indicator on endpoints where WinRAR's command-line tool has no legitimate business use.

## What This Dataset Contains

The dataset spans 3 seconds (2026-03-17 17:33:34–17:33:37 UTC) and contains 103 PowerShell events, 4 Security events, and 18 Sysmon events.

The attack command is fully preserved in Security EID 4688:
```
"cmd.exe" /c "%programfiles%/WinRAR/Rar.exe" a -r %USERPROFILE%\T1560.001-data.rar %USERPROFILE%\*.txt
```

And the cleanup:
```
"cmd.exe" /c del /f /q /s %USERPROFILE%\T1560.001-data.rar >nul 2>&1
```

Security EID 4688 records 4 process creation events: two `whoami.exe` pre- and post-execution checks, the WinRAR invocation via `cmd.exe`, and the cleanup `cmd.exe`. All run as `NT AUTHORITY\SYSTEM`.

Sysmon EID 1 captures 4 process creation events with full hashes: `whoami.exe`, the WinRAR `cmd.exe` wrapper (SHA256: `A6E3B3B22B7FE8CE2C9245816126723EAA13F43B9F591883E59959A2D409426A`), a second `whoami.exe`, and the cleanup `cmd.exe`. The WinRAR `cmd.exe` is tagged `RuleName: technique_id=T1059.003,technique_name=Windows Command Shell`. Parent-child relationship is recorded: both `cmd.exe` instances show `ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`.

Sysmon EID 7 records 9 ImageLoad events for the two PowerShell instances. Sysmon EID 10 records 4 ProcessAccess events (test framework output capture). Sysmon EID 17 records 1 named pipe creation.

The PowerShell events contain 100 EID 4104 script block logging events and 3 EID 4103 module logging events, consisting entirely of ART test framework boilerplate.

## What This Dataset Does Not Contain

No `Rar.exe` process creation appears. WinRAR is not installed at `%ProgramFiles%/WinRAR/Rar.exe` on this host. The `cmd.exe` wrapper executed, attempted to invoke the binary, received a file-not-found error, and exited — but `Rar.exe` itself never ran as a process. No Security EID 4688 or Sysmon EID 1 event for `Rar.exe` is present.

No `.rar` archive was created. No Sysmon EID 11 FileCreate event for `T1560.001-data.rar` appears. The technique failed at the prerequisite stage.

No `cmd.exe` exit code (Security EID 4689) events appear in the collection. In the defended variant, the `0x1` exit code from `cmd.exe` confirmed the failure. Here, the Security channel only collected EID 4688 (process creation), not EID 4689 (process exit) — so the failure is inferred from the absence of Rar.exe rather than an explicit exit code.

This contrasts directly with T1560-1: the PowerShell-native `Compress-Archive` approach succeeded because it requires no external binary, while this WinRAR approach failed due to a missing prerequisite.

## Assessment

This dataset captures a prerequisite-failure scenario. The command line that would archive data with WinRAR is fully preserved across Security EID 4688 and Sysmon EID 1. The archiving tool was absent, but the attacker's intent is clearly recorded: recursive archive of `.txt` files from the user profile into a `.rar` file at the user profile root.

Compared to the defended variant (26 Sysmon, 10 Security, 34 PowerShell events), this undefended run produced a nearly identical event structure (18 Sysmon, 4 Security, 103 PowerShell events). The main difference is the higher PowerShell 4104 count in the undefended run — 100 events versus 34 — reflecting the additional ART framework activity captured without Defender interruption. The Sysmon count is lower here (18 vs 26) because the defended run generated additional events from Defender's process inspection.

The security research value of this dataset is in demonstrating that the command line itself — the detection signal — is preserved regardless of whether the technique succeeds. You do not need the archive to have been created to detect this activity.

## Detection Opportunities Present in This Data

**Security EID 4688 command line**: `"cmd.exe" /c "%programfiles%/WinRAR/Rar.exe" a -r %USERPROFILE%\T1560.001-data.rar %USERPROFILE%\*.txt` from a SYSTEM PowerShell-spawned `cmd.exe`. The WinRAR recursive archive syntax (`a -r`) targeting the user profile is a documented intrusion indicator. The fact that the binary is absent does not reduce the detection value — the intent is recorded.

**Sysmon EID 1 parent-child chain**: `powershell.exe` (test framework) → `cmd.exe` (WinRAR invocation). The `cmd.exe` parent being `powershell.exe` running as SYSTEM, combined with a command line invoking a third-party archiving tool, is a meaningful behavioral combination.

**Cleanup command**: `del /f /q /s %USERPROFILE%\T1560.001-data.rar >nul 2>&1` appears in Security EID 4688. The ART cleanup is recorded even though no archive was created — in a real intrusion, a cleanup command following an archiving command suggests intentional artifact removal and is worth flagging even when the primary operation fails.

**Absence of Rar.exe**: If your detection logic expects to see `Rar.exe` in the process tree following the `cmd.exe` invocation and it is absent, that is an indicator of a specific execution environment. Defenders can detect the attempt from the `cmd.exe` command line alone without waiting for `Rar.exe` to appear.
