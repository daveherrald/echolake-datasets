# T1548.002-12: Bypass User Account Control — UACME Method 33

## Technique Context

UACME Method 33 exploits the `SilentCleanup` scheduled task, which runs with highest privileges
and is configured to run as the interactive user without a UAC prompt. By setting the
`%windir%` environment variable to a controlled path before triggering the task, an attacker can
cause `SilentCleanup` to execute an arbitrary payload from the spoofed system directory. The ART
test invokes: `cmd.exe /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\uacme\33 Akagi64.exe"`

## What This Dataset Contains

**Sysmon (26 events):** EID 7 (ImageLoad), EID 11 (FileCreated), EID 17 (PipeCreated),
EID 1 (ProcessCreate), EID 10 (ProcessAccess). Process creates:

- `whoami.exe` (ART pre-check, parent: PowerShell)
- `cmd.exe` with command line:
  `"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\uacme\33 Akagi64.exe"`
  (parent: PowerShell, rule: `T1059.003`)

EID 10 records PowerShell accessing `whoami.exe` and `cmd.exe` with `GrantedAccess: 0x1FFFFF`.
EID 11 captures PowerShell writing the startup profile data file (ambient PowerShell behavior).

**Security (10 events):** EID 4688/4689 and EID 4703. Two process creations: `whoami.exe` and
`cmd.exe`.

**PowerShell (34 events):** Boilerplate ART test framework scriptblocks and `Set-ExecutionPolicy -Bypass`
events. No technique-specific PowerShell content.

## What This Dataset Does Not Contain (and Why)

**No `SilentCleanup` task execution** — Windows Defender blocked Akagi64.exe before it could
manipulate the `%windir%` environment variable or trigger the scheduled task. No `svchost.exe`
task runner events, no `taskeng.exe` or `taskhostw.exe` spawning a payload, and no elevated
process tree from `cleanmgr.exe` (the normal SilentCleanup payload) appear in the data.

**No environment variable modification artifacts** — Sysmon does not natively capture environment
variable changes, and Akagi64.exe was blocked before making them.

**No Akagi64.exe process entry** — Defender prevented the binary from creating observable child
processes; no EID 4688 or Sysmon EID 1 record for Akagi64.exe itself is present.

**No logon or elevated token events** — the bypass never reached the elevation phase.

## Assessment

This dataset is structurally identical to Methods 23, 31, 39, and 56 in its outcome: Defender
blocked the UACME binary and only the cmd.exe invocation is logged. The technique-differentiating
detail — Method 33 vs. other UACME methods — is visible only in the method number in the
command line. The 26 Sysmon events (vs. 16 for Method 31) reflect slightly more DLL load activity,
likely due to Defender's inspection response.

## Detection Opportunities Present in This Data

- **Security EID 4688 / Sysmon EID 1:** `cmd.exe` command line containing `33 Akagi64.exe` or
  `ExternalPayloads\uacme\33` — method 33 is the `SilentCleanup` technique
- **Behavioral correlation:** Combining detection of Akagi64.exe invocation with monitoring for
  `SilentCleanup` scheduled task execution or `cleanmgr.exe` with unusual parent processes would
  detect a successful bypass that Defender misses
- **Sysmon EID 11:** File writes to PowerShell startup profile paths are ambient noise here;
  filtering these reduces false positives in correlation rules targeting EID 11 events
- **Environment variable monitoring** (not present in this dataset): Changes to `%windir%` or
  `%SystemRoot%` via registry or API would be a high-fidelity indicator of this specific method
