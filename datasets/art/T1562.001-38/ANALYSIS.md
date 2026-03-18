# T1562.001-38: Disable or Modify Tools — Disable or Modify Tools - Delete Windows Defender Scheduled Tasks

## Technique Context

T1562.001 (Disable or Modify Tools) includes removing scheduled tasks that keep Windows
Defender operational. Defender relies on several scheduled tasks for periodic scanning, cache
maintenance, cleanup, and signature verification. Deleting these tasks degrades Defender's
ability to perform scheduled scans and maintenance operations, reducing ongoing detection
coverage even if real-time protection remains enabled. This technique has been observed in
ransomware pre-attack preparation, where attackers remove maintenance tasks to prevent
Defender from refreshing signatures or performing integrity checks that might detect implants
before encryption begins.

## What This Dataset Contains

The test attempts to delete four Windows Defender scheduled tasks using conditional
`schtasks /delete` commands gated on `IF EXIST` file checks, executed as NT AUTHORITY\SYSTEM:

```
cmd.exe /c IF EXIST "%temp%\Windows_Defender_Scheduled_Scan.xml"
  ( schtasks /delete /tn "\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /f )
& IF EXIST "%temp%\Windows_Defender_Cleanup.xml"
  ( schtasks /delete /tn "\Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /f )
& IF EXIST "%temp%\Windows_Defender_Verification.xml"
  ( schtasks /delete /tn "\Microsoft\Windows\Windows Defender\Windows Defender Verification" /f )
& IF EXIST "%temp%\Windows_Defender_Cache_Maintenance.xml"
  ( schtasks /delete /tn "\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /f )
```

**Sysmon (26 events, EIDs 1, 7, 10, 11, 17):**
Two EID 1 ProcessCreate events are present: `whoami.exe` (ART test framework pre-flight, RuleName
`T1033`) and `cmd.exe` with the full schtasks command (RuleName `T1059.003/Windows Command
Shell`). The `cmd.exe` parent is the test framework `powershell.exe` running as SYSTEM, session 0.
`schtasks.exe` itself does not produce a Sysmon EID 1 — it is not in the sysmon-modular
include list. The remaining events are EID 7 ImageLoad entries for the PowerShell processes,
EID 11 file creation in the SYSTEM profile temp path, and EID 10 process access events.

**Security (10 events, EIDs 4688, 4689, 4703):**
4688 records `whoami.exe` and `cmd.exe` with the full multi-stage schtasks command verbatim.
`cmd.exe` exits with 0x0 (4689). A 4703 token adjustment event is present.

**PowerShell (34 events, EIDs 4103, 4104):**
Two 4103 events record `Set-ExecutionPolicy Bypass -Scope Process` (ART test framework boilerplate).
Remaining 32 events are 4104 script block entries for PowerShell's internal formatter stubs.
The attack commands run via `cmd.exe`, so no attack-specific PowerShell script blocks appear.

## What This Dataset Does Not Contain (and Why)

**Evidence that any tasks were actually deleted:** The `IF EXIST "%temp%\*.xml"` conditions
check for XML backup files before attempting deletion. If these files were not pre-staged by
an earlier ART prerequisite step, none of the `schtasks /delete` commands execute, and
`cmd.exe` still exits with 0x0. The exit code reflects that the conditional shell logic ran
without error, not that any tasks were removed. Whether the XML prerequisites existed in
the temp directory at execution time is not determinable from this dataset.

**Sysmon EID 1 for schtasks.exe:** The sysmon-modular include-mode configuration does not
include `schtasks.exe`. If any `schtasks /delete` commands did execute, they would not
appear in Sysmon. Security 4688 provides the full `cmd.exe` command line (including all
four task names) but only at the `cmd.exe` level — `schtasks.exe` as a separate process is
not captured in Security either, because it runs as an internal child of the cmd.exe
compound command, not as a separately audited process creation in all Windows versions.

**TaskScheduler operational events for task deletion:** The
Microsoft-Windows-TaskScheduler/Operational channel (EID 141 for task deletion) is not in
the Cribl Edge collection channels for this environment. Task deletion confirmations would
appear there if collected.

**Defender behavioral changes:** No changes to real-time protection, scan status, or
Defender alerting are observable within this short window.

## Assessment

This dataset demonstrates how conditional shell logic (`IF EXIST`) creates ambiguity about
whether an attack action actually executed. The `cmd.exe` exit code 0x0 confirms the shell
completed without error but is insufficient to determine whether any task was deleted. The
detection value of this dataset lies in the Security 4688 command line, which exposes all
four targeted task names regardless of whether the deletes ran. The sysmon-modular include
filter captures `cmd.exe` (via the T1059.003 Windows Command Shell rule) and thus preserves
the full attack command in Sysmon EID 1 as well, in contrast to T1562.001-37 where Sysmon
produced no process-creation evidence.

## Detection Opportunities Present in This Data

- **Sysmon EID 1 / Security 4688:** `cmd.exe /c` with `schtasks /delete /tn` targeting
  `\Microsoft\Windows\Windows Defender\` is a high-fidelity indicator. The task path prefix
  alone is sufficient for a reliable detection rule — no Defender scheduled task should be
  deleted by a non-interactive SYSTEM process.
- **Four-task deletion pattern:** The compound `&`-chained command targeting all four
  Defender maintenance tasks simultaneously is characteristic of an automated attack script
  rather than manual administration. Single-task deletion might be ambiguous; four targets
  in one shell invocation is not.
- **Process chain:** `powershell.exe` (SYSTEM, session 0, no script path) → `cmd.exe` with
  schtasks Defender task deletion is a specific ancestry pattern with no benign explanation.
- **PowerShell EID 4103:** `Set-ExecutionPolicy Bypass -Scope Process` as the first PS event
  in the session, followed immediately by `cmd.exe` with schtasks, is a recognizable
  test framework-style execution pattern.
- **Conditional guard as a signal:** The `IF EXIST` guard on `%temp%\*.xml` files before
  deletion is a characteristic of ART-style scripts that pre-export tasks before deleting
  them. Detection rules that match on the task names in the `schtasks /delete` command work
  regardless of whether the conditionals fire.
