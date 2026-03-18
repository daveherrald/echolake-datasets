# T1548.002-15: Bypass User Account Control — UACME Bypass Method 56

## Technique Context

UACME Method 56 targets `consent.exe` or related auto-elevate binaries using a DLL planting
or environment variable manipulation technique specific to that method number in the UACME
source. The ART test invokes:
`cmd.exe /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\uacme\56 Akagi64.exe"`

The `56` argument selects this variant from the UACME method table. Method 56 is one of the
higher-numbered methods in the UACME sequence and targets a mechanism present in Windows 10
and 11 builds.

## What This Dataset Contains

**Sysmon (16 events):** EIDs 7 (ImageLoad, 9), 10 (ProcessAccess, 3), 1 (ProcessCreate, 3),
17 (PipeCreate, 1). The event structure is identical to Methods 33, 34, and 39.

Key process-create events (EID 1):
- `whoami.exe` — ART pre-check, parent `powershell.exe`, `IntegrityLevel: System`
- `cmd.exe` — the UACME invocation:
  `CommandLine: "cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\uacme\56 Akagi64.exe"`
  parent `powershell.exe`, `RuleName: technique_id=T1059.003`,
  `Hashes: SHA256=A6E3B3B22B7FE8CE2C9245816126723EAA13F43B9F591883E59959A2D409426A`
- Second `whoami.exe` — ART post-check

EID 10: `powershell.exe` accessing `whoami.exe` and `cmd.exe` with `GrantedAccess: 0x1FFFFF`.

EID 7: Standard .NET runtime and PowerShell assembly DLL loads, plus `MpOAV.dll` from Defender.

**Security (3 events):** Three EID 4688 events: `whoami.exe` (pre-check), `cmd.exe` with the
Method 56 command line, `whoami.exe` (post-check). All `TokenElevationTypeDefault (1)`.

**PowerShell (97 events):** EIDs 4104 (96) and 4103 (1). One additional EID 4104 event
compared to Methods 33, 34, and 39 (97 vs. 96), within normal variance of the ART test framework
framework invocation. The EID 4103 entry is the `Set-ExecutionPolicy -Bypass` boilerplate.

## What This Dataset Does Not Contain

**No Akagi64.exe process create, no elevation artifacts.** The same limitations as Methods
33, 34, and 39 apply. Method 56 specific mechanism artifacts (DLL planting, file system
writes to elevation-related paths) are not observable in the current logging configuration.

**No UAC-related DLL loads.** If Method 56 involves planting a DLL that gets loaded by an
auto-elevating binary, those DLL load events (Sysmon EID 7 from the target auto-elevate
process) would be the primary artifacts. They do not appear in this dataset, suggesting the
bypass binary ran but the target auto-elevate process's activity was not captured.

**No elevated process.** No `TokenElevationTypeFull (2)` in any EID 4688.

## Assessment

All four UACME method tests (33, 34, 39, 56) in this batch produce an identical observable
telemetry pattern: 16 Sysmon events, 3 Security events, ~96 PowerShell events, with the
sole differentiating artifact being the method number in the `cmd.exe` command line. This
uniformity has direct implications for detection model training: a model trained on event
counts or event type distributions alone cannot distinguish between these methods. The
command line content is the only differentiator.

The defended run for Method 56 showed 16 Sysmon / 10 Security / 26 PowerShell events —
indicating that Defender generated 7 additional Security events and the undefended PowerShell
channel nearly quadruples (26 → 97). The near-identical Sysmon count (16 both ways) confirms
these UACME methods produce a fixed Sysmon footprint regardless of Defender state at this
logging level.

## Detection Opportunities Present in This Data

- **Security EID 4688 / Sysmon EID 1:** `cmd.exe` command line containing
  `ExternalPayloads\uacme\56` or `Akagi64.exe` with argument `56`.
- **UACME method pattern:** The full set of UACME method tests (33, 34, 39, 56) in this
  batch share the `ExternalPayloads\uacme\<N> Akagi64.exe` command line template. A single
  pattern matching `Akagi64.exe` with any numeric argument in a `cmd.exe` invocation will
  cover all four methods.
- **SHA256 of cmd.exe:** The `cmd.exe` binary itself has consistent hashes across tests
  (`SHA256=A6E3B3B22B7FE8CE2C9245816126723EAA13F43B9F591883E59959A2D409426A`) — this is the
  system `cmd.exe`, not the indicator; the hash of `Akagi64.exe` would be the meaningful IOC.
- **Sysmon EID 7:** Monitoring for `Akagi64.exe` loading any DLL from an unexpected path
  would capture Method 56's DLL-planting mechanism if Sysmon EID 7 coverage were extended
  to include the `Akagi64.exe` process.
