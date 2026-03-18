# T1548.002-3: Bypass User Account Control — Bypass UAC using Fodhelper

## Technique Context

T1548.002 (Bypass User Account Control) covers techniques that allow an attacker to
elevate from a standard user session to a high-integrity process without triggering the
UAC consent prompt. The Fodhelper bypass exploits the fact that `fodhelper.exe` is an
auto-elevating binary that reads a shell command handler from `HKCU\Software\Classes\ms-settings\shell\open\command`
before launching. Because the key lives in the per-user hive, it can be written without
administrative rights. When `fodhelper.exe` runs, it opens with high integrity and invokes
whatever command is stored there, giving the attacker an elevated shell.

This test uses the classic `cmd.exe`-based variant: a single compound command writes the
registry key, sets the `DelegateExecute` marker, and immediately launches `fodhelper.exe`.

## What This Dataset Contains

The dataset spans roughly five seconds of telemetry (00:03:46–00:03:51 UTC) and captures
the attempt and its immediate result.

**Security log (4688) — the attack command:**
```
"cmd.exe" /c reg.exe add hkcu\software\classes\ms-settings\shell\open\command
          /ve /d "C:\Windows\System32\cmd.exe" /f
          & reg.exe add hkcu\software\classes\ms-settings\shell\open\command
          /v "DelegateExecute" /f
          & fodhelper.exe
```
Parent: `powershell.exe` (the ART test framework). Token elevation type: `TokenElevationTypeDefault (1)`.

**Security log (4689) — Defender blocked the payload:**
The `cmd.exe` spawned by `fodhelper.exe` exits with status `0xC0000022`
(STATUS_ACCESS_DENIED). Windows Defender's behavior monitoring intercepted the
auto-elevation and denied execution. The data therefore represents an attempted bypass,
not a successful one.

**Sysmon Event 1 — process create for `whoami.exe`:**
The ART test framework runs `whoami.exe` as a pre-check, confirming execution context before the
bypass attempt. Parent is `powershell.exe`, IntegrityLevel = System (the test runs as
SYSTEM via QEMU guest agent).

**Sysmon Event 8 — CreateRemoteThread:**
`powershell.exe` created a remote thread in an unknown process (PID 5216 —
likely `fodhelper.exe` prior to being killed). RuleName tags this as T1055 (Process
Injection), an artifact of how Sysmon observes the PowerShell runtime spinning up child
processes, not a separate injection attempt.

**Sysmon Event 10 — ProcessAccess on `whoami.exe`:**
`powershell.exe` opens `whoami.exe` with full access rights (0x1FFFFF) as part of its
normal child-process management. Call trace runs through `System.Management.Automation.ni.dll`.

**PowerShell logs (4104/4103):**
Thirty-nine events — all PowerShell test framework boilerplate: `Set-ExecutionPolicy -Scope
Process -Force -ExecutionPolicy Bypass`, internal error-formatting closures, and module
loading. No script block content from the bypass itself was captured because the attack
payload was delivered via `cmd.exe`, not a PowerShell cmdlet.

## What This Dataset Does Not Contain (and Why)

- **The elevated `cmd.exe` shell payload executing.** Defender blocked the process at
  launch (exit code `0xC0000022`), so no commands ran inside the elevated shell.
- **Sysmon Event 13 (registry value set).** The Sysmon configuration uses include-mode
  filtering for ProcessCreate; the `reg.exe add` commands were invoked inside a `cmd.exe`
  chain. The sysmon-modular config does not capture registry writes from `reg.exe` for
  this key path in the bundled events (the reg writes show in Security 4688 command
  lines only).
- **`fodhelper.exe` process create.** The auto-elevated process was intercepted before
  it generated a process-create event visible to Sysmon, or the Sysmon include filter
  did not match `fodhelper.exe` directly at that event position.
- **HKCU registry cleanup.** ART performs per-test cleanup; the deletion of the
  `ms-settings` key is not present in this snapshot.

## Assessment

Windows Defender blocked the elevated payload before it could execute, producing attempt
telemetry rather than success telemetry. The dataset is forensically authentic: it shows
exactly the artifacts a responder would see when this technique is attempted on an
endpoint with active behavior monitoring. The full attack command line is present in the
Security log, which is the primary detection surface.

## Detection Opportunities Present in This Data

- **Security 4688:** `cmd.exe` command line contains `ms-settings\shell\open\command`,
  `DelegateExecute`, and `fodhelper.exe` in a single compound command — a high-fidelity
  indicator.
- **Security 4689:** `cmd.exe` exits with `0xC0000022` immediately after a `fodhelper`
  launch — indicates a blocked elevation attempt.
- **Sysmon Event 1:** `whoami.exe` spawned by `powershell.exe` without an interactive
  session token is a common pre-attack recon pattern.
- **Sysmon Event 8 (CreateRemoteThread):** `powershell.exe` as source with an unknown
  target process is worth correlating with the 4688 command line.
- **Sysmon Event 4703 (token right adjusted):** The enabling of high-privilege rights
  (`SeBackupPrivilege`, `SeRestorePrivilege`, `SeLoadDriverPrivilege`, etc.) on
  `powershell.exe` is detectable even when the downstream bypass is blocked.
