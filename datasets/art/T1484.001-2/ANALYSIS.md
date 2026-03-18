# T1484.001-2: Group Policy Modification — LockBit Black - Modify Group policy settings (Powershell)

## Technique Context

T1484.001 (Group Policy Modification) covers adversary abuse of Group Policy to weaken defenses
across a domain. This test replicates the same LockBit Black group policy modification sequence
as T1484.001-1 — writing the same six registry keys under `HKLM\SOFTWARE\Policies\Microsoft\
Windows\System` — but uses PowerShell's `New-ItemProperty` cmdlet instead of `reg.exe`. This is
the PowerShell variant of the technique, which produces a distinct telemetry profile across all
three log channels.

## What This Dataset Contains

This dataset captures telemetry from a PowerShell script block that calls `New-ItemProperty` six
times to write the LockBit Black Group Policy registry keys on ACME-WS02.

**Security channel (4688/4689)** provides the technique command line. A 4688 event records the
full PowerShell script block: six `New-ItemProperty` calls targeting
`HKLM:\SOFTWARE\Policies\Microsoft\Windows\System` with the same key names and values as the
cmd variant. The PowerShell process exits with `0x0` — all six registry writes succeeded.

**PowerShell channel** (43 events, IDs 4103/4104) contains meaningful technique telemetry in
addition to the test framework boilerplate. Module logging (ID 4103) events later in the file capture
individual `New-ItemProperty` cmdlet invocations with full parameter bindings, including the
registry path, value name, data type, and value for each call. This provides a second independent
record of each registry modification, corroborating the Security 4688 command line with per-
invocation detail. Specifically, 4103 events confirm: `EnableSmartScreen` = 0 and
`ShellSmartScreenLevel` with Force parameter — evidence of individual cmdlet execution rather
than just the overall command line.

**Sysmon channel** (46 events, IDs 1, 7, 10, 11, 17) captures the powershell.exe child process
via ProcessCreate (ID 1). Sysmon ID 7 (ImageLoad) events document the .NET runtime and PowerShell
management automation assembly loading. Unlike the cmd variant (T1484.001-1), there are no
individual reg.exe child processes to track — the registry writes happen within the PowerShell
process itself.

## What This Dataset Does Not Contain

- Security registry audit events (4657/4663) — policy change auditing is set to `none`
- Individual per-key Sysmon or Security events for each `New-ItemProperty` call (the PowerShell
  channel's 4103 events provide this granularity instead)
- Any evidence of Defender intervention — exit code `0x0` confirms clean completion

## Assessment

This dataset provides **complementary coverage** to T1484.001-1 for the same LockBit Black
technique. The PowerShell variant produces richer logging in the PowerShell channel (4103 module
logging with per-cmdlet parameter bindings) while producing a single powershell.exe process rather
than six reg.exe child processes. Defenders should note that the detection profile differs: the
cmd variant is detectable via multiple child process 4688 events, while this variant requires
either PowerShell channel analysis or the parent process command line to identify the full sequence.

## Detection Opportunities Present in This Data

- **Security 4688**: PowerShell command line containing `New-ItemProperty` + `HKLM:\SOFTWARE\
  Policies\Microsoft\Windows\System` + `GroupPolicyRefreshTime` or `EnableSmartScreen` is the
  primary indicator
- **PowerShell 4103**: Module logging captures each `New-ItemProperty` invocation with path,
  name, type, and value as distinct parameter binding entries — useful for per-key detections
  even when the command line is obfuscated or split across multiple script blocks
- **Sysmon ID 1**: powershell.exe spawned by powershell.exe with `New-ItemProperty` and the
  Group Policy registry path in the command line
- **Behavioral comparison**: Pairing T1484.001-1 (reg.exe) and T1484.001-2 (PowerShell) in
  detection development helps ensure both delivery mechanisms for this LockBit pattern are
  covered; the registry key names (`GroupPolicyRefreshTimeDC`, `EnableSmartScreen`, etc.) are
  the constant across both variants
