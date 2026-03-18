# T1548.002-11: Bypass User Account Control — UACME Method 31

## Technique Context

UACME Method 31 exploits the Windows `IFileOperation` COM interface, which runs in the context
of an auto-elevating process. By triggering a file copy operation through this interface, an
attacker can write files to protected directories (such as `System32`) without a UAC prompt.
A malicious DLL planted in a trusted location can then be loaded by an auto-elevating binary,
resulting in elevated code execution. The ART test invokes:
`cmd.exe /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\uacme\31 Akagi64.exe"`

## What This Dataset Contains

**Sysmon (16 events):** EID 7 (ImageLoad), EID 11 (FileCreated), EID 17 (PipeCreated),
EID 1 (ProcessCreate), EID 10 (ProcessAccess). This is the smallest Sysmon event count in the
T1548.002 series. Process creates:

- `whoami.exe` (ART pre-check, parent: PowerShell)
- `cmd.exe` with command line:
  `"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\uacme\31 Akagi64.exe"`
  (parent: PowerShell, rule: `T1059.003`)

EID 10 (ProcessAccess) captures PowerShell accessing `whoami.exe` and `cmd.exe` with
`GrantedAccess: 0x1FFFFF` (rule: `T1055.001`).

**Security (10 events):** EID 4688/4689 and EID 4703. The two process creations are `whoami.exe`
and `cmd.exe`. No child processes from Akagi64.exe appear.

**PowerShell (34 events):** Entirely boilerplate ART test framework scriptblocks and
`Set-ExecutionPolicy -Bypass`. No attack-specific content.

## What This Dataset Does Not Contain (and Why)

**No Akagi64.exe process creation or child processes** — as with other UACME tests in this series,
Windows Defender (fully active with version 4.18.26010.5) blocks the UACME binary. The process
creation event for `Akagi64.exe` does not appear in either Security or Sysmon logs, indicating
the binary was blocked before it could create observable child processes. UACME binaries carry
known Defender signatures.

**No file system bypass artifacts** — Method 31's `IFileOperation` writes would appear as file
creation events in `System32` or other protected paths. None are present, confirming the bypass
did not execute.

**No elevated process chain** — no token elevation type 2 (elevated token) process trees appear.

**No logon events** — unlike Methods 34 and 1, this method did not produce 4624/4672 events,
consistent with the bypass failing before reaching the elevation stage.

## Assessment

This dataset captures the **attempt** telemetry for UACME Method 31: the cmd.exe invocation of
Akagi64.exe is documented in Security EID 4688 and Sysmon EID 1. The technique itself was blocked
by Defender before execution. The dataset is structurally similar to Methods 23, 33, 39, and 56
in this series — all show the same pattern of test framework invocation followed by Defender blocking
Akagi64.exe. The primary differentiator between these datasets is the method number passed to
Akagi64.exe.

## Detection Opportunities Present in This Data

- **Security EID 4688 / Sysmon EID 1:** `cmd.exe` command line referencing `Akagi64.exe` with
  method number `31` — or any numeric argument preceding `Akagi64.exe`
- **Security EID 4688 / Sysmon EID 1:** `powershell.exe → cmd.exe` with the
  `ExternalPayloads\uacme\` path pattern
- **Process count anomaly:** Only two meaningful process creations in a short window (whoami +
  cmd) is a thin footprint; combine with command-line content to raise confidence
- **Sysmon EID 10:** Full-access handle (`0x1FFFFF`) from PowerShell to cmd.exe children is a
  consistent artifact of the ART UACME test framework wrapper and can serve as a corroborating signal
