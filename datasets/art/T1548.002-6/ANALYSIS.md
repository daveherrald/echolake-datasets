# T1548.002-6: Bypass User Account Control — Bypass UAC by Mocking Trusted Directories

## Technique Context

T1548.002 (Bypass User Account Control) includes directory-spoofing approaches in
addition to registry-based hijacks. The "mocking trusted directories" technique exploits
a Windows path-parsing inconsistency: the UAC elevation logic considers a binary trusted
if it resides in a path beginning with `C:\Windows\System32\`, but path normalization
routines that strip trailing spaces produce a directory that Windows allows non-privileged
users to create — `C:\Windows \System32\` (note the trailing space before the backslash).
An attacker creates this directory, copies a known-trusted auto-elevating binary (here
`mmc.exe`) into it, then creates a symlink at a user-writable path pointing to the fake
binary. When UAC evaluates the symlink target's path, the space causes it to match the
trusted-directory prefix and auto-elevate without prompting.

## What This Dataset Contains

The dataset spans roughly four seconds of telemetry (00:04:43–00:04:47 UTC).

**Security 4688 — the attack command:**
```
"cmd.exe" /c mkdir "\\?\C:\Windows \System32\"
          & copy "C:\Windows\System32\cmd.exe" "\\?\C:\Windows \System32\mmc.exe"
          & mklink c:\testbypass.exe "\\?\C:\Windows \System32\mmc.exe"
```
The `\\?\` prefix bypasses the Win32 path length and normalization rules, allowing the
creation of the directory with the embedded space. The command copies `cmd.exe` as
`mmc.exe` (a known auto-elevating binary name) and creates a symlink at `C:\testbypass.exe`.

**Sysmon Event 11 (file creates) — the planted files:**
```
C:\Windows \System32\mmc.exe   (Image: cmd.exe)
C:\testbypass.exe               (Image: cmd.exe)
```
These are the two artifacts created by the bypass setup. The path `C:\Windows \System32\mmc.exe`
with its trailing space is a strong indicator — legitimate `mmc.exe` lives at
`C:\Windows\System32\mmc.exe` without a space.

**Sysmon Event 1 — process creates:**
- `whoami.exe` (ART pre-check, IntegrityLevel=System, parent `powershell.exe`)
- `cmd.exe` (payload, Sysmon RuleName T1083 File and Directory Discovery, parent
  `powershell.exe`)

**Sysmon Event 10 — ProcessAccess on `whoami.exe`:**
`powershell.exe` opens `whoami.exe` with full access (0x1FFFFF) as part of child-process
management.

**Security 4703 — token rights adjusted on `powershell.exe`:**
Multiple high-privilege rights enabled, consistent with SYSTEM context.

## What This Dataset Does Not Contain (and Why)

- **Successful auto-elevation of `testbypass.exe`.** The test creates the directory
  structure and symlink but does not show a successful elevated launch. The bundled
  events end after the file creation phase; whether `testbypass.exe` was subsequently
  executed is not captured.
- **`mmc.exe` or `testbypass.exe` process create.** The Sysmon include-mode filter
  does not explicitly match these binaries in the fake directory path, and the elevation
  trigger appears to be outside the telemetry window.
- **Sysmon Event 13 (registry).** This technique does not involve registry manipulation;
  accordingly no registry events appear.
- **Directory creation events.** The `mkdir` via `\\?\` path creates a directory, not a
  file, so Sysmon Event 11 (FileCreate) does not record it. The directory creation is
  only visible via the 4688 command line.

## Assessment

The most forensically significant artifacts in this dataset are the Sysmon Event 11
entries showing file creation at the space-embedded path
`C:\Windows \System32\mmc.exe`. The presence of a file whose path differs from the
legitimate System32 path only by a trailing space is an unambiguous indicator.
The full attack command including `\\?\` path manipulation is present in the Security
4688 log, providing a second high-confidence detection surface.

## Detection Opportunities Present in This Data

- **Sysmon Event 11:** File created at a path matching `C:\Windows \` (space before
  backslash) — a near-zero false-positive indicator of directory mocking.
- **Security 4688:** Command line contains `\\?\C:\Windows \System32\` — the `\\?\`
  prefix combined with a space-containing Windows path is highly suspicious.
- **Security 4688:** `mklink` creating `C:\testbypass.exe` as a symlink — a symlink
  at the root of C: pointing into a fake System32 directory is anomalous.
- **Sysmon Event 11:** `cmd.exe` writing a file named `mmc.exe` to a non-standard
  path — binary name mismatch with expected parent directory.
- **Process lineage:** `cmd.exe` spawned by `powershell.exe` with `\\?\` in the
  command line is worth flagging for review.
