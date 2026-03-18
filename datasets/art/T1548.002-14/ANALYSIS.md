# T1548.002-14: Bypass User Account Control — UACME Method 39

## Technique Context

UACME Method 39 abuses the `ColorDataProxy` / `CMLuaUtil` COM object, which is registered as
an auto-elevating in-process server. By invoking specific methods on this COM object from a
medium-integrity process, an attacker can execute arbitrary commands at high integrity without
a UAC prompt. The ART test invokes:
`cmd.exe /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\uacme\39 Akagi64.exe"`

## What This Dataset Contains

**Sysmon (16 events):** EID 7 (ImageLoad), EID 11 (FileCreated), EID 17 (PipeCreated),
EID 1 (ProcessCreate), EID 10 (ProcessAccess). The two EID 1 events are:

- `whoami.exe` (ART pre-check, parent: PowerShell)
- `cmd.exe` with command line:
  `"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\uacme\39 Akagi64.exe"`
  (parent: PowerShell, rule: `T1059.003`)

EID 10 records PowerShell accessing `whoami.exe` and `cmd.exe` with `GrantedAccess: 0x1FFFFF`.
EID 11 captures the PowerShell startup profile data file write (ambient).

**Security (10 events):** EID 4688/4689 and EID 4703. Two process creations: `whoami.exe` and
`cmd.exe`. This is among the minimal event footprints in the T1548.002 series.

**PowerShell (22 events):** Boilerplate ART test framework scriptblocks and `Set-ExecutionPolicy -Bypass`.
The smaller count compared to other tests (22 vs. 34) suggests a slightly different test framework
invocation path, but all events are non-technique-specific.

## What This Dataset Does Not Contain (and Why)

**No COM object interaction telemetry** — UACME Method 39's `CMLuaUtil` COM abuse does not
produce Windows Event Log entries for COM instantiation. ETW-based COM tracing would be required
to observe the CoCreateInstance call, and that collection is not in scope for this dataset.

**No elevated process from the COM method** — Defender blocked `Akagi64.exe` before it could
invoke the COM object. No `dllhost.exe` surrogate processes or elevated child processes appear.

**No Akagi64.exe process record** — same pattern as Methods 23, 31, 33, and 56.

**No logon events** — unlike Method 34, no ambient service logons occurred during this test
window. The test completed in approximately 4 seconds.

## Assessment

Method 39 produces the same blocked-attempt pattern as the other UACME tests. The dataset is
the smallest in the series (22 PowerShell events vs. 34 for most others, 16 Sysmon events).
The only differentiator from Methods 23, 31, 33, and 56 in observable telemetry is the method
number `39` in the `cmd.exe` command line. This dataset is most useful as part of the full
UACME series for understanding what Defender-blocked UACME invocations look like across multiple
methods.

## Detection Opportunities Present in This Data

- **Security EID 4688 / Sysmon EID 1:** `cmd.exe` command line with `39 Akagi64.exe` or
  `ExternalPayloads\uacme\39`
- **Behavioral (not in this dataset):** Successful Method 39 bypass would show `dllhost.exe`
  (COM surrogate) spawning a high-integrity process — monitoring for `dllhost.exe` creating child
  processes with `TokenElevationType=2` is a broader COM abuse detection
- **Sysmon EID 10:** Full-access PowerShell handle to cmd.exe is a consistent pattern across all
  UACME tests in this series; combined with the command-line content it is a reliable compound
  indicator
- **Temporal analysis:** The entire test (whoami check + cmd launch) completes in under 1 second,
  creating a tight temporal cluster useful for correlation rules
