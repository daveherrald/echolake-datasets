# T1548.002-13: Bypass User Account Control — UACME Bypass Method 34

## Technique Context

UACME Method 34 exploits `slui.exe` (Software Licensing UI), which is configured
`autoElevate: true` in its manifest. By writing a malicious payload path into a specific
registry key that `slui.exe` reads on launch, an attacker can trigger slui.exe to spawn
the payload with elevated privileges. The ART test invokes:
`cmd.exe /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\uacme\34 Akagi64.exe"`

The `34` argument selects the slui.exe variant from UACME's method table.

## What This Dataset Contains

**Sysmon (16 events):** EIDs 7 (ImageLoad, 9), 10 (ProcessAccess, 3), 1 (ProcessCreate, 3),
17 (PipeCreate, 1). The event structure is structurally identical to Method 33 (T1548.002-12).

Key process-create events (EID 1):
- `whoami.exe` — ART pre-check, parent `powershell.exe`,
  `CommandLine: "C:\Windows\system32\whoami.exe"`, `IntegrityLevel: System`
- `cmd.exe` — UACME invocation:
  `CommandLine: "cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\uacme\34 Akagi64.exe"`
  parent `powershell.exe`, `RuleName: technique_id=T1059.003`
- Second `whoami.exe` — ART post-check

EID 10 (ProcessAccess): `powershell.exe` accessing `whoami.exe` and `cmd.exe` with
`GrantedAccess: 0x1FFFFF` — standard PowerShell process-launch access pattern.

EID 7 events show the same .NET runtime DLL loads (`mscoree.dll`, `mscoreei.dll`, `clr.dll`,
`mscorlib.ni.dll`, `clrjit.dll`, `System.Management.Automation.ni.dll`) and `MpOAV.dll`.

**Security (3 events):** Three EID 4688 events: `whoami.exe` (pre-check), `cmd.exe` with the
Method 34 command line, and `whoami.exe` (post-check). All with
`TokenElevationTypeDefault (1)` and `MandatoryLabel: S-1-16-16384`.

**PowerShell (96 events):** EIDs 4104 (95) and 4103 (1). Identical pattern to Method 33:
one ART test framework `Set-ExecutionPolicy -Bypass` EID 4103 event, and 95 EID 4104 script-block
events covering the framework invocation.

## What This Dataset Does Not Contain

**No Akagi64.exe process create, no slui.exe process create.** The bypass mechanism does not
produce observable child process events in this dataset. Method 34's slui.exe manipulation
(which typically involves writing a CLSID handler under `HKCU\Software\Classes\CLSID`) is not
captured in Sysmon EID 13 events here.

**No registry modification artifacts.** The HKCU CLSID key writes that enable the slui.exe
bypass are not present in the Sysmon EID 12/13 samples. This contrasts with tests `-4` and
`-27` where registry manipulation is more directly observable.

**No elevated token event.** No EID 4688 with `TokenElevationTypeFull (2)` appears.

## Assessment

This dataset is structurally identical to Method 33 (T1548.002-12): 16 Sysmon events, 3
Security events, 96 PowerShell events, same EID breakdown, same process tree. The only
distinguishing artifact between the two datasets is the method number in the command line
(`34` here vs. `33` in T1548.002-12). The defended run showed more events (28 Sysmon / 16
Security / 34 PowerShell), with the Security channel having 16 events due to Defender's
additional process creation activity during inspection. In the undefended run, the Security
channel returns to 3 events — the bare minimum for this test pattern.

The identical telemetry pattern across Methods 33, 34, 39, and 56 (tests -12, -13, -14, -15)
illustrates a key limitation of event-count-based detection: all four methods produce the
same observable footprint at this logging configuration, with the method number in the command
line being the sole differentiator.

## Detection Opportunities Present in This Data

- **Security EID 4688 / Sysmon EID 1:** `cmd.exe` command line containing
  `ExternalPayloads\uacme\34` or `Akagi64.exe` with method number `34`.
- **Sysmon EID 1:** `Akagi64.exe` in any process create with a numeric argument — the
  method number maps to a specific UACME bypass mechanism. Method 34 targets `slui.exe`.
- **Path anomaly:** Non-canonical path with `..` traversal in
  `C:\AtomicRedTeam\atomics\..\ExternalPayloads\uacme\`.
- **Behavioral grouping:** The identical event structure across Methods 33/34/39/56 means
  that a single rule matching `Akagi64.exe` with any numeric argument covers all four UACME
  method tests in this batch.
