# T1548.002-10: Bypass User Account Control — UACME Method 23

## Technique Context

UACME is an open-source UAC bypass research toolkit (Akagi64.exe) documenting dozens of distinct
bypass techniques. Method 23 exploits the ISecurityEditor COM interface exposed by the Windows
Setup API to modify security descriptors on HKLM keys without elevation, then plants a malicious
DLL or command that gets loaded by an auto-elevating process. The ART test invokes:
`cmd.exe /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\uacme\23 Akagi64.exe"`

## What This Dataset Contains

**Sysmon (26 events):** EID 7 (ImageLoad), EID 11 (FileCreated), EID 17 (PipeCreated),
EID 1 (ProcessCreate), EID 10 (ProcessAccess). Process creates:

- `whoami.exe` (ART pre-check, parent: PowerShell)
- `cmd.exe` with command line:
  `"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\uacme\23 Akagi64.exe"`
  (parent: PowerShell, rule: `T1059.003`)

EID 10 (ProcessAccess) events show PowerShell accessing `whoami.exe` and `cmd.exe` with
`GrantedAccess: 0x1FFFFF` — a full-access handle, attributed to rule `T1055.001 DLL Injection`.
This is a Sysmon-modular artifact of how the ART test framework uses `Start-Process` with process
handle acquisition, not actual injection.

**Security (11 events):** EID 4688/4689 and EID 4703. Two process creations: `whoami.exe` and
`cmd.exe` with the Akagi64.exe invocation. No additional child processes from Akagi64 are present.

**PowerShell (34 events):** Entirely boilerplate ART test framework internal scriptblocks and
`Set-ExecutionPolicy -Bypass` calls. No attack-specific PowerShell code — the technique was
invoked entirely via `cmd.exe`.

**WMI (1 event):** EID 5858 — a WMI query failure:
`SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = 'wsmprovhost.exe'`
with `ResultCode = 0x80041032` (WBEM_E_NOT_SUPPORTED). This is ambient system monitoring
activity unrelated to the UACME attempt.

**System (1 event):** EID 7040 — Background Intelligent Transfer Service changed from auto
start to demand start. Ambient OS activity.

## What This Dataset Does Not Contain (and Why)

**No Akagi64.exe process creation** — `cmd.exe` launched `Akagi64.exe` but no EID 1 (Sysmon) or
EID 4688 (Security) record for it appears in the filtered dataset. The sysmon-modular include-mode
ProcessCreate config does not have a rule matching `Akagi64.exe` or the ExternalPayloads path,
so it was not captured. Security EID 4688 would capture it with command-line logging, but it is
absent — Akagi64.exe either exited before audit policy flushed, was blocked before creating a
process, or the process creation event fell outside the dataset time window.

**No bypass execution chain** — no elevated process spawned by the bypass is present. Windows
Defender's behavioral monitoring was active, and UACME binaries are well-known signatures.

**No registry or file artifact events** — Sysmon EID 13 (SetValue) or EID 11 (FileCreated) for
the bypass mechanism's artifacts are absent.

## Assessment

This dataset captures the **test framework invocation** of UACME Method 23 — the PowerShell-to-cmd
launch chain is fully documented — but not the bypass mechanism itself. The absence of Akagi64.exe
in process creation logs is likely due to Defender blocking it at the process level (status
`0xC0000022`, access denied) before it could execute meaningfully. The dataset is useful for
detecting the ART invocation pattern and the characteristic `Akagi64.exe` path in command lines.

## Detection Opportunities Present in This Data

- **Security EID 4688 / Sysmon EID 1:** `cmd.exe` command line containing `Akagi64.exe` or
  paths matching `ExternalPayloads\uacme\`
- **Security EID 4688 / Sysmon EID 1:** `cmd.exe` spawned by `powershell.exe` with numeric
  method arguments (e.g., `23 Akagi64.exe`) is characteristic of UACME invocation
- **Sysmon EID 10:** PowerShell with `GrantedAccess: 0x1FFFFF` to child `cmd.exe` may indicate
  process handle harvesting used for parent-process spoofing or monitoring
- **WMI EID 5858:** WMI query failures for `Win32_ProcessStartTrace` can indicate tooling that
  monitors for elevated process creation as a bypass verification step
