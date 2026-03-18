# T1548.002-27: Bypass User Account Control — UAC Bypass via ProgIDs Registry

## Technique Context

This test bypasses UAC by abusing Windows ProgID class registration. The technique creates a
custom ProgID (`.pwn`) with an `Open` command pointing to `calc.exe`, then sets the
`ms-settings\CurVer` key to point to `.pwn`. When `fodhelper.exe` (auto-elevating) reads its
`ms-settings` COM handler and follows the `CurVer` indirection to the `.pwn` ProgID, it
executes `calc.exe` with elevated privileges. This is a ProgID redirection variant of the
fodhelper bypass — distinct from the direct `ms-settings\shell\open\command` manipulation in
tests `-3` and `-4`. The full `cmd.exe` command line is:
`"cmd.exe" /c reg add "HKEY_CURRENT_USER\Software\Classes\.pwn\Shell\Open\command" /ve /d "C:\Windows\System32\calc.exe" /f &  & reg add "HKEY_CURRENT_USER\Software\Classes\ms-settings\CurVer" /ve /d ".pwn" /f &  & echo Triggering fodhelper.exe for potential privilege escalation... & start fodhelper.exe`

## What This Dataset Contains

**Sysmon (20 events):** EIDs 7 (ImageLoad, 9), 1 (ProcessCreate, 6), 10 (ProcessAccess, 4),
17 (PipeCreate, 1).

Key process-create events (EID 1):
- `whoami.exe` — ART pre-check, parent `powershell.exe`, `IntegrityLevel: System`
- `cmd.exe` — the full ProgID manipulation and fodhelper launch command line (above)
  parent `powershell.exe`, `RuleName: technique_id=T1059.003`
- `whoami.exe` — post-check, parent `powershell.exe`
- Cleanup `cmd.exe`:
  `"cmd.exe" /c reg delete "HKEY_CURRENT_USER\Software\Classes\.pwn\Shell\Open\command" /ve /f & reg delete "HKEY_CURRENT_USER\Software\Classes\ms-settings\CurVer" /ve /f`
  (parent `powershell.exe`)

**Security (6 events):** Six EID 4688 events:
- `whoami.exe` (pre-check)
- Setup `cmd.exe` with the full ProgID + fodhelper command
- Second `whoami.exe` (post-check)
- Cleanup `cmd.exe` with `reg delete` commands
- `reg.exe` deleting `"HKEY_CURRENT_USER\Software\Classes\.pwn\Shell\Open\command" /ve /f`
  (parent: cleanup `cmd.exe`)
- `reg.exe` deleting `"HKEY_CURRENT_USER\Software\Classes\ms-settings\CurVer" /ve /f`
  (parent: cleanup `cmd.exe`)

The cleanup `reg.exe` invocations are captured as individual EID 4688 events, providing
direct evidence of the specific keys the attacker wrote during the bypass — attackers
clean up these exact keys after the bypass.

**PowerShell (97 events):** EIDs 4104 (96) and 4103 (1). Single `Set-ExecutionPolicy -Bypass`
EID 4103 event; 96 EID 4104 script-block events.

## What This Dataset Does Not Contain

**No fodhelper.exe process create.** Although the setup `cmd.exe` calls `start fodhelper.exe`,
`fodhelper.exe` does not appear as a separate EID 4688 or Sysmon EID 1 event in the samples.
The Sysmon include filter may not match `fodhelper.exe` by name, and it may fall outside the
Security audit sample window.

**No elevated calc.exe child.** The expected payload — `calc.exe` spawned by `fodhelper.exe`
with high integrity — does not appear. Running as SYSTEM makes the elevation semantics moot.

**No Sysmon EID 12/13 for the registry key writes.** The `reg.exe` invocations that write
`HKCU\Software\Classes\.pwn\Shell\Open\command` and `HKCU\Software\Classes\ms-settings\CurVer`
do not generate Sysmon registry events in the samples. Only the cleanup operations via
Security EID 4688 (`reg delete`) are directly logged.

## Assessment

This dataset has the most Security EID 4688 events of any UACME/non-WinPwn test in this
batch (6 events), because the cleanup uses two separate `reg.exe` invocations that are each
captured. The cleanup `reg.exe` command lines are forensically valuable: they reveal the
exact registry keys used during setup — `HKCU\Software\Classes\.pwn\Shell\Open\command` and
`HKCU\Software\Classes\ms-settings\CurVer` — even though the setup commands themselves used
`cmd.exe /c reg add` (which was captured) and the `reg.exe` setup subprocesses were not
individually logged.

The test uses `calc.exe` as the payload (same as test 19), not `cmd.exe`. The cleanup
`reg.exe` commands are direct reverse-engineering artifacts that map precisely to the keys
written during the attack, providing a complete picture of the bypass mechanism.

Compared to the defended run (26 Sysmon / 11 Security / 34 PowerShell), the undefended run
shows fewer Sysmon events (20 vs. 26) and slightly fewer Security events (6 vs. 11),
indicating Defender was generating 5 Security and 6 Sysmon events through its own response.

## Detection Opportunities Present in This Data

- **Security EID 4688 / Sysmon EID 1:** `cmd.exe` command line containing both
  `HKEY_CURRENT_USER\Software\Classes\.pwn\Shell\Open\command` and
  `HKEY_CURRENT_USER\Software\Classes\ms-settings\CurVer` — the ProgID redirection setup.
- **Security EID 4688:** `cmd.exe` invoking `start fodhelper.exe` is anomalous as a
  shell-launched operation.
- **Security EID 4688 (cleanup):** `reg.exe` deleting `ms-settings\CurVer` and any custom
  ProgID key under `HKCU\Software\Classes` — cleanup is a strong indicator of prior
  bypass activity.
- **Correlation:** The sequence `reg add .pwn\Shell\Open\command` → `reg add ms-settings\CurVer`
  → `fodhelper.exe` → `reg delete .pwn` → `reg delete ms-settings\CurVer` within a 5-second
  window is a complete behavioral fingerprint of this technique.
- **Sysmon EID 13:** Any process writing to `HKCU\Software\Classes\ms-settings\CurVer`
  outside of normal application installation is a high-fidelity indicator of ProgID-based
  fodhelper bypass preparation.
