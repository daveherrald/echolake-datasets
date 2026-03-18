# T1548.002-3: Bypass User Account Control — Bypass UAC using Fodhelper

## Technique Context

Fodhelper (`C:\Windows\System32\fodhelper.exe`) is a Windows optional feature manager that is
marked `autoElevate: true` in its manifest, meaning it runs elevated without a UAC prompt when
invoked by a standard user. It consults `HKCU\Software\Classes\ms-settings\shell\open\command`
before the machine-level equivalent. By writing a payload into that per-user key and setting the
`DelegateExecute` value to an empty string (which triggers the COM elevation path), an attacker
can cause fodhelper to spawn an elevated process of their choosing. Test `-3` performs this
manipulation via `cmd.exe` invoking `reg.exe`, in contrast to test `-4` which uses PowerShell
directly.

## What This Dataset Contains

**Sysmon (15 events):** EIDs 7 (ImageLoad, 9), 1 (ProcessCreate, 2), 10 (ProcessAccess, 2),
17 (PipeCreate, 1), 8 (CreateRemoteThread, 1).

Key events:

EID 1 — `whoami.exe` (ART pre-check, parent `powershell.exe`, `IntegrityLevel: System`)

EID 1 — second `whoami.exe` (ART post-check, same parent chain)

EID 8 — `CreateRemoteThread` from `powershell.exe` (PID 12004) into an unknown process
(PID 18028, `TargetImage: <unknown process>`), `StartAddress: 0x00007FF7818C0570`,
`StartModule: -`. This is a highly notable event: Sysmon detected that the ART test framework
PowerShell spawned a remote thread in what was likely `fodhelper.exe` or the elevated payload,
but the process exited or was unmapped before Sysmon could resolve the image name.

**Security (3 events):** Three EID 4688 events: `whoami.exe` (pre-check), `cmd.exe` with the
complete registry-manipulation command line:
`"cmd.exe" /c reg.exe add hkcu\software\classes\ms-settings\shell\open\command /ve /d "C:\Windows\System32\cmd.exe" /f & reg.exe add hkcu\software\classes\ms-settings\shell\open\command /v "DelegateExecute" /f & fodhelper.exe`
and `whoami.exe` (post-check). All three have `TokenElevationTypeDefault (1)` and
`MandatoryLabel: S-1-16-16384` (System integrity).

**PowerShell (99 events):** EIDs 4104 (95), 4103 (2), 4100 (2). The EID 4103 entries are
ART test framework boilerplate. The EID 4100 events indicate a PowerShell pipeline engine error,
likely from the process cleanup or environment teardown step.

## What This Dataset Does Not Contain

**No fodhelper.exe process create entry.** Although the Security EID 4688 command line shows
`fodhelper.exe` was invoked as part of the `cmd.exe` chain, `fodhelper.exe` itself does not
appear as a named process in the Sysmon EID 1 or Security EID 4688 samples. This is consistent
with the Sysmon process-create filter being include-only for suspicious patterns — `fodhelper.exe`
may not match the configured include rules, and the Security audit captures only events within
the sample window. The EID 8 `CreateRemoteThread` to an unknown PID is the closest telemetry
to the actual elevation event.

**No elevated cmd.exe child.** The expected output of a successful fodhelper bypass is a new
`cmd.exe` running at high integrity (TokenElevationTypeFull) as a child of `fodhelper.exe`.
No such event appears in the Security or Sysmon channels, possibly because the test runs as
`SYSTEM` (already fully privileged) and the bypass path's elevation output is not distinguishable
or is not separately logged.

**No reg.exe process entries.** The Security 4688 events show `cmd.exe` launching the full
`reg.exe add ... & fodhelper.exe` chain, but individual `reg.exe` subprocesses are not present
in the samples, unlike test `-27` which captures `reg.exe` cleanup invocations.

## Assessment

The EID 8 `CreateRemoteThread` from `powershell.exe` into an unknown (exited) process is the
most forensically distinctive event in this dataset. In real-world hunting, an ART test framework
PowerShell creating a remote thread in any process — particularly one that exits before its
image can be resolved — would be a high-priority alert. The Security EID 4688 command line
for `cmd.exe` includes the complete registry manipulation and `fodhelper.exe` invocation in a
single shell one-liner, providing strong evidence of the bypass attempt even without the
elevated result process. Compared to the defended run (15 Sysmon / 9 Security events), this
undefended dataset has essentially the same Sysmon count but adds three Security events
and substantially more PowerShell script-block content (99 vs. 39 events).

## Detection Opportunities Present in This Data

- **Security EID 4688 / Sysmon EID 1:** `cmd.exe` command line containing both
  `ms-settings\shell\open\command` registry manipulation and `fodhelper.exe` in the same
  invocation.
- **Security EID 4688:** `reg.exe add hkcu\software\classes\ms-settings\shell\open\command`
  with `/v "DelegateExecute"` — the empty DelegateExecute value is required to trigger the
  COM elevation path; its presence in HKCU is not legitimate.
- **Sysmon EID 8:** `CreateRemoteThread` from `powershell.exe` into any process with
  `StartModule: -` (unresolved module) warrants immediate investigation.
- **Sysmon EID 1 (if fodhelper present):** `fodhelper.exe` spawning any process other than
  the optional features UI components is inherently suspicious.
