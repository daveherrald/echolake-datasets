# T1548.002-27: Bypass User Account Control — UAC bypassed by Utilizing ProgIDs registry

## Technique Context

T1548.002 (Bypass User Account Control) includes ProgID-based registry hijacks as a
variant of the class-handler redirection family. This technique creates a custom file
extension ProgID (`.pwn`) that maps to a command handler (`C:\Windows\System32\calc.exe`),
then sets `HKCU\Software\Classes\ms-settings\CurVer` to point to the new ProgID. When
`fodhelper.exe` auto-elevates and resolves `ms-settings`, it follows the `CurVer`
redirection to `.pwn` and executes the command handler registered there.

This is a variant of the direct `ms-settings\shell\open\command` write (tests 3 and 4):
instead of placing the payload command directly in the `ms-settings` shell handler, it
registers a custom ProgID and redirects `ms-settings` to it. The indirection may evade
simple monitors checking only the `ms-settings\shell\open\command` path.

The payload is delivered via `cmd.exe` using `reg.exe` calls.

## What This Dataset Contains

The dataset spans roughly five seconds of telemetry (00:11:35–00:11:40 UTC).

**Security 4688 — two process creates:**
1. `whoami.exe` — ART pre-check, parent `powershell.exe`
2. `cmd.exe` with the full attack command:
   ```
   "cmd.exe" /c reg add "HKEY_CURRENT_USER\Software\Classes\.pwn\Shell\Open\command"
                        /ve /d "C:\Windows\System32\calc.exe" /f
             & reg add "HKEY_CURRENT_USER\Software\Classes\ms-settings\CurVer"
                       /ve /d ".pwn" /f
             & echo Triggering fodhelper.exe for potential privilege escalation...
             & start fodhelper.exe
   ```
   Token elevation type: `TokenElevationTypeDefault (1)`.

**Sysmon Event 1 — two process creates:**
- `whoami.exe` (T1033 rule)
- `cmd.exe` (T1059.003 rule) — the compound command chain

**Security 4689 — `cmd.exe` exits with status `0x1`:**
The compound command returned exit code 1. The most probable cause is that `fodhelper.exe`
was intercepted by Defender after the registry writes completed. The writes themselves
likely succeeded (they do not require elevation), but the elevated launch was blocked.

## What This Dataset Does Not Contain (and Why)

- **Sysmon Event 13 (registry writes).** The `reg.exe` calls within the `cmd.exe` chain
  did not generate Sysmon Event 13 entries in the bundled dataset. The sysmon-modular
  config's include-mode filtering matches specific registry key paths for T1548.002; the
  `.pwn` ProgID path and `ms-settings\CurVer` may not be explicitly covered by the
  current ruleset version, resulting in the writes being captured in Security 4688
  command lines only.
- **`fodhelper.exe` process create.** The Sysmon include filter did not capture it, and
  Defender's behavior monitoring blocked the auto-elevation before a visible elevated
  child was spawned.
- **Elevated `calc.exe` (the payload).** The exit code 1 and absence of elevated process
  events confirm the bypass did not succeed.
- **The `.pwn` ProgID key creation as a dedicated Sysmon event.** Only the Security
  4688 command line captures both registry writes in this dataset.

## Assessment

This dataset demonstrates the ProgID-indirection variant of the Fodhelper bypass family.
The registry manipulation is visible only via the Security 4688 command line, not via
Sysmon Event 13, highlighting the importance of command-line auditing as a complementary
detection layer when Sysmon include-mode filtering does not cover all relevant registry
paths. The `CurVer` redirection pattern is a known evasion of `ms-settings\shell\open\
command` monitors, and this dataset provides a representative example for tuning
detections to cover both the direct and indirect write paths.

## Detection Opportunities Present in This Data

- **Security 4688:** `cmd.exe` command line containing `ms-settings\CurVer` and a
  custom ProgID — the `CurVer` redirection to a non-standard ProgID is the distinguishing
  indicator of this variant.
- **Security 4688:** `reg add` targeting `HKCU\Software\Classes\.pwn\Shell\Open\command`
  — creating a new file-extension ProgID with a shell command handler is unusual outside
  of software installers.
- **Security 4688:** `fodhelper.exe` appearing in a compound command following registry
  manipulation — same high-fidelity pattern as tests 3 and 4.
- **Security 4689:** `cmd.exe` exit code `0x1` after a `fodhelper.exe`-containing
  command — consistent with a blocked UAC bypass attempt.
- **Sysmon Event 1 (T1059.003):** `cmd.exe` with `reg add` + `CurVer` + `fodhelper`
  in the command line, spawned by `powershell.exe`.
