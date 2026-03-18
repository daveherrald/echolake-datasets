# T1548.002-14: Bypass User Account Control — UACME Bypass Method 39

## Technique Context

UACME Method 39 exploits the Windows 10/11 `AppInfo` service consent flow via a COM interface
(`ICMLuaUtil`) that allows a COM object to request elevation without a UAC prompt when called
from an already-elevated context or via a specific protocol handler. The ART test invokes:
`cmd.exe /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\uacme\39 Akagi64.exe"`

The `39` argument selects this specific COM-based variant from UACME's method table.

## What This Dataset Contains

**Sysmon (16 events):** EIDs 7 (ImageLoad, 9), 10 (ProcessAccess, 3), 1 (ProcessCreate, 3),
17 (PipeCreate, 1). The pattern is structurally identical to Methods 33 and 34.

Key process-create events (EID 1):
- `whoami.exe` — ART pre-check, parent `powershell.exe`, `IntegrityLevel: System`
- `cmd.exe`:
  `CommandLine: "cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\uacme\39 Akagi64.exe"`
  parent `powershell.exe`, `RuleName: technique_id=T1059.003`
- Second `whoami.exe` — post-check

EID 10 (ProcessAccess): `powershell.exe` → `whoami.exe` and `powershell.exe` → `cmd.exe`,
both with `GrantedAccess: 0x1FFFFF`.

EID 7: Same .NET runtime and PowerShell DLL load set as other UACME tests in this batch.

**Security (4 events):** Four EID 4688 events: `whoami.exe` (pre-check), `cmd.exe` with the
Method 39 command line, a second `whoami.exe`, and a fourth 4688 event (additional whoami or
process in the test window). All show `TokenElevationTypeDefault (1)`.

**PowerShell (96 events):** EIDs 4104 (95) and 4103 (1). Same ART test framework boilerplate pattern;
one `Set-ExecutionPolicy -Bypass` EID 4103 event and 95 EID 4104 script-block events.

## What This Dataset Does Not Contain

**No Akagi64.exe process create.** Method 39 runs and the `cmd.exe` is captured, but
`Akagi64.exe` itself does not appear as a separate process create event. The ICMLuaUtil COM
interface interactions are not visible in process-level telemetry.

**No COM activation artifacts.** The `AppInfo` service consent interactions and DCOM object
creation calls that Method 39 uses are not captured by any of the three logging channels at
this configuration. EID 4688 does not log service-level COM activations, and Sysmon does not
include WMI or COM broker events by default.

**No elevated token event.** No `TokenElevationTypeFull (2)` appears in any EID 4688 record.

## Assessment

Method 39 produces one more Security EID 4688 event (4 total) than Methods 33 and 34 (3 each),
suggesting a slightly different process execution sequence during the test — possibly an
additional process creation in the cleanup or the Akagi64 execution window. The core observable
artifacts are the same: the `cmd.exe` command line naming `uacme\39 Akagi64.exe` identifies the
method uniquely.

The defended run (T1548.002-14 defended) showed identical Sysmon (16 events) and similar
Security (10 events) counts — the undefended run has 4 Security events vs. 10, confirming
Defender was generating 6 additional process-create records through its own monitoring
instrumentation in the defended environment. The PowerShell channel expands from 22 to 96
events without Defender suppression.

## Detection Opportunities Present in This Data

- **Security EID 4688 / Sysmon EID 1:** `cmd.exe` command line containing
  `ExternalPayloads\uacme\39` or `Akagi64.exe` with argument `39`.
- **Method 39 context:** UACME Method 39 uses `ICMLuaUtil`, a COM interface exploited via
  the AppInfo service. Monitoring DCOM activation events (Application event log, EID 10010)
  for `ICMLuaUtil` class activation from unexpected parent processes may provide an
  additional detection layer not present in this dataset.
- **Path anomaly:** Non-canonical `C:\AtomicRedTeam\atomics\..\ExternalPayloads\uacme\`
  path in the command line.
- **Sysmon EID 10:** `powershell.exe` accessing `cmd.exe` with full access immediately
  before a UACME invocation.
