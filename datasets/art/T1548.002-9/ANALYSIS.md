# T1548.002-9: Bypass User Account Control — Bypass UAC using SilentCleanup task

## Technique Context

T1548.002 (Bypass User Account Control) includes scheduled-task-based bypasses. This
test abuses the built-in `SilentCleanup` scheduled task, which runs `%windir%\system32\
cleanmgr.exe` with the `highestAvailable` run level — causing it to auto-elevate without
a UAC prompt. The bypass works by setting the `%windir%` environment variable for the
current user to an attacker-controlled directory, so when the task fires it executes an
attacker binary instead of the real `cleanmgr.exe`. The task can be triggered
programmatically with `schtasks /run /tn "Microsoft\Windows\DiskCleanup\SilentCleanup"`.

The ART test executes the logic through a batch script at
`C:\AtomicRedTeam\atomics\T1548.002\src\T1548.002.bat`.

## What This Dataset Contains

The dataset spans roughly four seconds of telemetry (00:05:40–00:05:44 UTC).

**Security 4688 — two process creates:**
1. `whoami.exe` — ART pre-check, parent `powershell.exe`
2. `cmd.exe`:
   ```
   "cmd.exe" /c "C:\AtomicRedTeam\atomics\T1548.002\src\T1548.002.bat"
   ```
   Both show `TokenElevationTypeDefault (1)` and Mandatory Label `S-1-16-16384`
   (System). The batch file path confirms this is the ART-packaged implementation of
   the SilentCleanup technique.

**Sysmon Event 1 — two process creates:**
- `whoami.exe` (RuleName: T1033)
- `cmd.exe` (RuleName: T1059.003) — the batch file launcher

**Security 4689 — `cmd.exe` exits with status `0x1`:**
The batch file returned exit code 1, indicating an error condition. Combined with the
absence of `schtasks.exe` or elevated-payload events, this confirms the technique did
not achieve a successful elevation on this endpoint.

**PowerShell logs (4103/4104):** Twenty-six events — all PowerShell test framework boilerplate
(error-formatting closures, `Set-ExecutionPolicy` invocations). The batch file itself
does not use PowerShell, so no script block content from the SilentCleanup technique
appears in the PowerShell logs.

## What This Dataset Does Not Contain (and Why)

- **`schtasks.exe` execution.** The ART batch script is expected to call `schtasks /run`
  to trigger `SilentCleanup`, but no `schtasks.exe` process create event appears. This
  suggests the batch file failed before reaching that step (exit code 1), likely because
  the environment-variable substitution or required prerequisite state was not satisfied
  under the SYSTEM execution context.
- **The `SilentCleanup` task spawning a payload.** No elevated child process was created
  as a result of the technique.
- **Sysmon Event 13 (registry writes).** The SilentCleanup bypass operates via
  environment variable manipulation, not registry writes; accordingly no Event 13 is
  present.
- **Detailed bat file content.** The PowerShell test framework only shells out to `cmd.exe`;
  the bat file's internal commands are not captured in PowerShell script block logs.
  The batch file's internal commands are not visible in 4688 events because the shell
  does not echo each sub-command as a new process creation unless the commands invoke
  new executables.

## Assessment

This dataset captures an attempted SilentCleanup UAC bypass that failed at the batch
file stage (exit code 1). The telemetry is representative of what analysts see when an
ART-packaged technique fails its prerequisite checks: a `cmd.exe` launch with a known
Atomic bat file path, a non-zero exit code, and an absence of downstream activity.
The batch file path itself is a strong indicator of Atomic Red Team execution, useful
for identifying test runs in an environment.

## Detection Opportunities Present in This Data

- **Security 4688:** `cmd.exe` spawning a file at `C:\AtomicRedTeam\atomics\T1548.002\src\`
  — direct evidence of Atomic Red Team execution; also matches the SilentCleanup
  technique path.
- **Security 4689:** `cmd.exe` exit code `0x1` immediately following a T1548.002 bat
  file launch — indicates a failed UAC bypass attempt.
- **Sysmon Event 1 (T1059.003):** `cmd.exe` with a `.bat` file argument from a known
  ART atomics path.
- **Process lineage:** `powershell.exe` → `cmd.exe /c *.bat` from `C:\AtomicRedTeam\`
  is a clear indicator of automated adversary simulation.
- **Absence of `schtasks.exe`:** In a successful SilentCleanup attack, expect
  `schtasks.exe /run /tn "*SilentCleanup*"` to follow; its absence here confirms the
  failed state.
