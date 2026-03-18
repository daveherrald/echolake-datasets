# T1546.008-2: Accessibility Features — Replace Binary of Sticky Keys

## Technique Context

T1546.008 (Accessibility Features) covers the abuse of Windows accessibility programs to obtain persistent access or privilege escalation. This test exercises the file replacement variant: the attacker overwrites `sethc.exe` (Sticky Keys, invoked by pressing Shift five times at the logon screen) with `cmd.exe`. Because accessibility features can be invoked from the Windows logon screen without authenticating, this substitution produces a SYSTEM-level command prompt accessible to anyone with physical or RDP access to the machine — no credentials required.

To perform the replacement, the attacker must first take ownership of a protected system binary and grant themselves write permissions. The test uses `takeown.exe` and `icacls.exe` to do this explicitly, making the full attack chain visible in logs. File replacement attacks on accessibility binaries have been documented in active use since at least 2013 and are associated with APT groups targeting Windows infrastructure over RDP.

In the defended variant of this test, Windows Defender's file integrity protections typically block or reverse the final `copy` step. Here, with Defender disabled, the replacement completes fully.

## What This Dataset Contains

The dataset spans 3 seconds (2026-03-17 17:07:02–17:07:05 UTC) on ACME-WS06 (`acme.local`), executing as `NT AUTHORITY\SYSTEM`.

**Sysmon (20 events — Event IDs 1, 7, 10, 11, 17):**

Sysmon EID 1 (ProcessCreate) records the full attack chain:

1. `whoami.exe` — test framework context check, tagged `technique_id=T1033`
2. `cmd.exe` with the compound command line:
   ```
   "cmd.exe" /c IF NOT EXIST C:\Windows\System32\sethc_backup.exe (copy C:\Windows\System32\sethc.exe C:\Windows\System32\sethc_backup.exe) ELSE ( pushd ) & takeown /F C:\Windows\System32\sethc.exe /A & icacls C:\Windows\System32\sethc.exe /grant Administrators:F /t & copy /Y C:\Windows\System32\cmd.exe C:\Windows\System32\sethc.exe
   ```
   This single command line contains all four steps: backup, ownership takeover, permission grant, and binary replacement.
3. `takeown.exe /F C:\Windows\System32\sethc.exe /A` — tagged `technique_id=T1222.001`
4. `icacls.exe C:\Windows\System32\sethc.exe /grant Administrators:F /t` — tagged `technique_id=T1222.001`

Sysmon EID 11 (FileCreate) confirms that `C:\Windows\System32\sethc_backup.exe` was written (the original `sethc.exe` backup), and critically, that `C:\Windows\System32\sethc.exe` itself was overwritten — the copy of `cmd.exe` onto the target succeeded. The `CreationUtcTime` on the written `sethc.exe` reflects `cmd.exe`'s original timestamp, consistent with a binary copy.

Sysmon EID 10 (ProcessAccess) records `powershell.exe` accessing `whoami.exe` and `cmd.exe` child processes with `GrantedAccess: 0x1FFFFF`, tagged `technique_id=T1055.001`. This is standard ART test framework behavior.

Sysmon EID 7 (ImageLoad, 9 events) records .NET runtime DLLs (`mscoree.dll`, `mscoreei.dll`, `clr.dll`) and PowerShell automation DLLs loading into the test framework `powershell.exe`. Sysmon EID 17 (PipeCreate) records the PowerShell named pipe `\PSHost.134182408218082624.13588.DefaultAppDomain.powershell`.

**Security (4 events — Event ID 4688):**

Four process creation events corroborate the Sysmon chain: `whoami.exe`, `cmd.exe` (with the full compound command line), and two additional `whoami.exe` invocations from the cleanup test framework. All create under `NT AUTHORITY\SYSTEM` (S-1-5-18, Logon ID 0x3E7).

**PowerShell (107 events — Event IDs 4103, 4104):**

Predominantly test framework boilerplate. EID 4104 (ScriptBlock logging) captures the outer ART wrapper and internal housekeeping functions. No payload-specific PowerShell scripts are present — the attack used `cmd.exe` and native Windows tools, not PowerShell.

## What This Dataset Does Not Contain

- **No Defender interference:** In the defended variant, Application log EID 15 events record Defender detecting and reacting to the file modification. Those events are absent here — Defender was disabled and the replacement proceeded without interruption.
- **No registry artifacts:** Unlike T1546.008-1 (IFEO debugger variant), this test does not write registry keys. There are no Sysmon EID 13 (RegistrySetValue) events.
- **No cleanup artifacts:** The ART cleanup step restores `sethc.exe` from the backup. The cleanup itself would generate a second file write to `sethc.exe`, but it falls outside this dataset's timestamp window.
- **No logon-screen trigger:** The dataset captures the setup only. The persistence payload fires when an unauthenticated user invokes Sticky Keys at the logon screen — that execution is not represented here.
- **pnputil / driver artifacts:** Not applicable to this technique.

## Assessment

This dataset provides a complete, unobstructed record of a Sticky Keys binary replacement attack. The critical artifact — the actual overwrite of `C:\Windows\System32\sethc.exe` — is confirmed by Sysmon EID 11. The full attack chain from ownership takeover through binary replacement is visible in a single `cmd.exe` command line captured by both Sysmon EID 1 and Security EID 4688. This is a high-fidelity, forensically complete representation of the technique.

The undefended dataset is notably smaller (20 Sysmon events) than the defended variant (29 Sysmon events). The defended variant's additional events come from Defender's defensive reactions. Here, the attack completes cleanly and quickly with no defensive overhead.

## Detection Opportunities Present in This Data

- **Sysmon EID 1:** `takeown.exe` executed against a System32 binary (`C:\Windows\System32\sethc.exe`) from a `powershell.exe` parent running as SYSTEM. Ownership operations on protected system binaries are rare in normal operations.
- **Sysmon EID 1:** `icacls.exe` granting `Administrators:F` on a System32 binary, again from SYSTEM context. The `/t` flag (recursive) on a single binary is also unusual.
- **Sysmon EID 1 / Security EID 4688:** `cmd.exe` with a command line that includes both `takeown` and `copy /Y ... sethc.exe` in a single compound statement is an extremely high-confidence indicator.
- **Sysmon EID 11:** A `FileCreate` event targeting `C:\Windows\System32\sethc.exe` where the creating process is `cmd.exe` (not a Windows Update or trusted installer process). Any write to an accessibility binary in System32 by a non-system-installer process is anomalous.
- **Sysmon EID 11:** Creation of `C:\Windows\System32\sethc_backup.exe` — the existence of a `_backup` file alongside a protected binary is a behavioral indicator of the replacement pattern.
