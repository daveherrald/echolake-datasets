# T1548.002-15: Bypass User Account Control — UACME Method 56

## Technique Context

UACME Method 56 abuses the `CMSTPLUA` COM interface exposed by `cmstp.exe` (Connection Manager
Profile Installer), which auto-elevates. By triggering `ShellExec` through this interface, an
attacker can cause `cmstp.exe` to execute an arbitrary command at high integrity without a UAC
prompt. This is an evolution of the broader class of COM-based auto-elevation bypasses. The
ART test invokes:
`cmd.exe /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\uacme\56 Akagi64.exe"`

## What This Dataset Contains

**Sysmon (16 events):** EID 7 (ImageLoad), EID 11 (FileCreated), EID 17 (PipeCreated),
EID 1 (ProcessCreate), EID 10 (ProcessAccess). The two EID 1 events:

- `whoami.exe` (ART pre-check, parent: PowerShell)
- `cmd.exe` with command line:
  `"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\uacme\56 Akagi64.exe"`
  (parent: PowerShell, rule: `T1059.003`)

EID 10 records PowerShell accessing `whoami.exe` and `cmd.exe` with `GrantedAccess: 0x1FFFFF`.
EID 11 is the PowerShell startup profile data file write (ambient).

**Security (10 events):** EID 4688/4689 and EID 4703. Two process creations: `whoami.exe` and
`cmd.exe`.

**PowerShell (26 events):** Boilerplate ART test framework scriptblocks and `Set-ExecutionPolicy -Bypass`.
Slightly fewer events than Methods 10-13, consistent with minor variations in test framework state across
sequential test runs.

## What This Dataset Does Not Contain (and Why)

**No `cmstp.exe` execution** — Defender blocked Akagi64.exe before it could invoke the CMSTPLUA
COM interface. No `cmstp.exe` process creation, no `cmstp.exe` launching a child, and no elevated
process tree appear.

**No COM interaction telemetry** — same limitation as Method 39. ETW COM tracing is not in scope.

**No Akagi64.exe process record** — consistent with all other UACME tests in this series.

**No registry or file artifacts from the bypass** — Method 56 does not require persistent registry
writes, and none are present.

## Assessment

Method 56 produces the minimal blocked-attempt footprint seen across all UACME tests in this
series. The dataset is structurally identical to Methods 23, 31, 33, and 39 from a telemetry
perspective. Method 56 (CMSTPLUA / cmstp.exe) is particularly notable because `cmstp.exe` is a
well-known LOLBin that is sometimes overlooked in detection coverage. A successful execution of
this method — not observed here due to Defender — would be detectable by monitoring `cmstp.exe`
for child process spawning or INF file loading.

## Detection Opportunities Present in This Data

- **Security EID 4688 / Sysmon EID 1:** `cmd.exe` command line with `56 Akagi64.exe` or
  `ExternalPayloads\uacme\56`
- **Behavioral (not in this dataset):** Successful Method 56 bypass would show `cmstp.exe`
  spawning a child process — monitoring for any `cmstp.exe` child process creation is a high-
  fidelity detection for this method family
- **Sysmon EID 1 rule:** `cmstp.exe` launching arbitrary executables should be tagged with
  LOLBin detection rules; the sysmon-modular config's accessibility bypass rules would likely
  capture it
- **Series-level pattern:** All six UACME tests (Methods 23, 31, 33, 34, 39, 56) show the same
  `powershell.exe → cmd.exe → <N> Akagi64.exe` invocation pattern; a single rule detecting any
  `Akagi64.exe` or `ExternalPayloads\uacme\` path reference covers all of them
