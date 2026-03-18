# T1558.004-1: AS-REP Roasting — Rubeus asreproast

## Technique Context

AS-REP Roasting (T1558.004) targets domain accounts that have Kerberos pre-authentication disabled — an account attribute set by an administrator, typically to support legacy applications or misconfiguration. When pre-authentication is disabled, the KDC will return an AS-REP message encrypted with the account's password hash without requiring the requestor to prove knowledge of the password first. An attacker can request these AS-REP responses for any such accounts and crack the encrypted portion offline. Rubeus is the primary tool used for this technique, providing the `asreproast` command that enumerates vulnerable accounts and collects their AS-REP hashes.

## What This Dataset Contains

The dataset spans approximately 6 seconds on 2026-03-14 from ACME-WS02 (acme.local domain) and contains 103 events across Sysmon, Security, and PowerShell channels.

**The attack command**, captured in Security 4688 and PowerShell 4104:
```
powershell.exe & {cmd.exe /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\rubeus.exe" asreproast /outfile:"C:\AtomicRedTeam\atomics\..\ExternalPayloads\rubeus_output.txt"}
```

**Rubeus.exe was blocked.** The `cmd.exe` process exits with status `0x1`. Rubeus.exe does not appear as a process in Security 4688 or Sysmon 1 — Defender prevented the binary from launching. No output file was written.

**Process chain** (Security 4688 and Sysmon 1):
1. `whoami.exe` — ART test framework identity pre-check (T1033)
2. `powershell.exe` — carrying the full rubeus command (T1059.001)
3. `cmd.exe` — spawned to launch rubeus.exe; exits 0x1 (T1059.003)

**Sysmon events include:**
- Event 1: `whoami.exe`, `powershell.exe` (T1059.001), `cmd.exe` (T1059.003)
- Event 7: .NET CLR image loads into PowerShell
- Event 10: PowerShell accessing child processes (T1055.001 pattern)
- Event 11: PowerShell startup profile data files
- Event 17: `\PSHost.*` named pipes

**PowerShell 4104** captures both the outer `& { cmd.exe /c "...rubeus.exe" asreproast ... }` wrapper and the inner body, making the full attack command visible in script block logging.

**PowerShell 4103** captures `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass` from the ART test framework.

## What This Dataset Does Not Contain (and Why)

**No Rubeus execution.** Defender blocked rubeus.exe before it could run. There is no Security 4688 or Sysmon 1 event for rubeus.exe itself.

**No AS-REP hashes collected.** The `asreproast` command never reached the KDC. No Kerberos AS-REQ/AS-REP traffic was generated, and no output file was written to disk.

**No Kerberos AS-REP events.** DC-side AS-REP responses (which would be visible as Security 4768 on the domain controller) are absent because no requests were made. This dataset covers only the workstation.

**No PowerShell 4100 error.** The block occurred in the external process (`cmd.exe` attempting to launch rubeus.exe), not within the PowerShell script context, so no 4100 event was generated in the PowerShell log.

## Assessment

Defender blocked Rubeus.exe before the AS-REP roasting attack could begin. This is the same pattern as test T1558.003-2 (Rubeus kerberoast) — Defender recognizes Rubeus by hash or reputation and prevents execution. The dataset is valuable as a record of the AS-REP roasting attack setup: the full command line referencing `asreproast` and `/outfile:` is preserved. For defenders, the `cmd.exe` exit code 0x1 combined with the command line referencing a path matching `\ExternalPayloads\rubeus.exe` is a reliable post-block detection signal.

## Detection Opportunities Present in This Data

- **Security 4688 / Sysmon 1**: `powershell.exe` command line containing `rubeus.exe asreproast` — `asreproast` is an unambiguous indicator of AS-REP Roasting intent
- **Security 4688**: `cmd.exe` carrying the rubeus asreproast command with `/outfile:` argument — the output file path reveals intent to persist collected hashes
- **PowerShell 4104**: Script block containing `cmd.exe /c "...rubeus.exe" asreproast` — logged before AMSI evaluation of the external binary
- **Security 4689**: `cmd.exe` exits with status `0x1` — failure exit code consistent with Defender blocking the child process
- **Sysmon 1**: PowerShell tagged `T1059.001` spawning `cmd.exe` tagged `T1059.003` as part of a lateral execution chain — process lineage is anomalous for legitimate workstation activity
