# T1548.002-12: Bypass User Account Control — UACME Bypass Method 33

## Technique Context

UACME Method 33 exploits the `SilentCleanup` scheduled task, which runs as the interactive
user with highest privileges without triggering a UAC prompt. By setting the `%windir%`
environment variable to a controlled path before triggering the task, an attacker causes
`SilentCleanup` to execute an arbitrary payload from the spoofed system directory location.
The ART test invokes this via:
`cmd.exe /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\uacme\33 Akagi64.exe"`

The method number (33) passed to `Akagi64.exe` selects the SilentCleanup variant from
UACME's method table.

## What This Dataset Contains

**Sysmon (16 events):** EIDs 7 (ImageLoad, 9), 10 (ProcessAccess, 3), 1 (ProcessCreate, 3),
17 (PipeCreate, 1).

Key process-create events (EID 1):
- `whoami.exe` — ART pre-check, parent `powershell.exe`,
  `CommandLine: "C:\Windows\system32\whoami.exe"`, `IntegrityLevel: System`
- `cmd.exe` — the UACME invocation:
  `CommandLine: "cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\uacme\33 Akagi64.exe"`
  parent `powershell.exe`, `RuleName: technique_id=T1059.003`, `IntegrityLevel: System`
- Second `whoami.exe` — ART post-check

EID 10 (ProcessAccess) records `powershell.exe` accessing each of `whoami.exe` and `cmd.exe`
with `GrantedAccess: 0x1FFFFF` (full access) — the normal pattern for PowerShell launching
processes via `Start-Process` or `Invoke-Expression`.

EID 7 (ImageLoad) events show `powershell.exe` loading .NET runtime components
(`mscoree.dll`, `mscoreei.dll`, `clr.dll`, `mscorlib.ni.dll`, `clrjit.dll`),
`System.Management.Automation.ni.dll` (tagged `technique_id=T1059.001`),
and `MpOAV.dll` from the Defender platform directory (tagged `technique_id=T1574.002`).

**Security (3 events):** Three EID 4688 events: `whoami.exe` (pre-check), `cmd.exe` with the
full Akagi64 command line, and `whoami.exe` (post-check). All show
`TokenElevationTypeDefault (1)` and `MandatoryLabel: S-1-16-16384` (System integrity).

**PowerShell (96 events):** EIDs 4104 (95) and 4103 (1). The single EID 4103 event is the
ART test framework `Set-ExecutionPolicy -Bypass`. The 95 EID 4104 events are script-block logs
covering the ART framework invocation but not technique-specific PowerShell content, since
the attack binary is launched via `cmd.exe` rather than through PowerShell cmdlets.

## What This Dataset Does Not Contain

**No Akagi64.exe process create.** The `cmd.exe` invocation targets
`C:\AtomicRedTeam\atomics\..\ExternalPayloads\uacme\33 Akagi64.exe`, but `Akagi64.exe`
does not appear as a separate EID 4688 or Sysmon EID 1 event. In the undefended environment,
Akagi64 was allowed to run — but with the test executing as `NT AUTHORITY\SYSTEM`, the UAC
bypass mechanism (environment variable manipulation → scheduled task trigger) may complete
without generating observable child processes within the log window, or the Sysmon include
filter does not match `Akagi64.exe`.

**No SilentCleanup task execution artifacts.** Method 33's mechanism involves triggering the
`SilentCleanup` scheduled task. No `taskhostw.exe` or `cleanmgr.exe` process-create events,
and no `svchost.exe`-rooted task execution chain, appear in the dataset. Compare with test
`-2` which captures a `4702` scheduled task update event during a related window; no task
modification artifacts are present here.

**No environment variable modification.** Sysmon does not natively capture `SetEnvironmentVariable`
calls. The key attacker action — setting `%windir%` to a malicious path — leaves no direct
artifact in any of the three channels.

**No elevated token event.** There is no EID 4688 with `TokenElevationTypeFull (2)` showing
a successfully elevated process launch.

## Assessment

Compared to the defended run (26 Sysmon / 10 Security / 34 PowerShell events), this undefended
dataset is notably smaller (16 / 3 / 96). The defended run had more Sysmon events because
Defender's inspection response generated additional DLL load and process access events; the
undefended run shows the baseline footprint. The Security channel drops from 10 to 3 events
because Defender was contributing process creation noise in the defended run. PowerShell
increases from 34 to 96 events because AMSI no longer suppresses any script-block logging.
The technique-identifying information — the method number `33` in the command line — is visible
in both Sysmon EID 1 and Security EID 4688.

## Detection Opportunities Present in This Data

- **Security EID 4688 / Sysmon EID 1:** `cmd.exe` command line containing
  `ExternalPayloads\uacme\33` or `Akagi64.exe` with a method number argument.
- **Sysmon EID 1:** Any invocation of `Akagi64.exe` with a numeric first argument corresponds
  to a specific UACME method; the method number should be cross-referenced against the UACME
  method table to understand the specific bypass mechanism.
- **Path anomaly:** The `..` traversal in `C:\AtomicRedTeam\atomics\..\ExternalPayloads\uacme\`
  is not normalized by Windows before logging, making it detectable as a non-canonical path
  in command line fields.
- **Sysmon EID 10:** `powershell.exe` accessing `cmd.exe` with `GrantedAccess: 0x1FFFFF`
  immediately before a UACME-related command line in `cmd.exe`.
