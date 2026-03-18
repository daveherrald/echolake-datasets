# T1484.001-1: Group Policy Modification — LockBit Black - Modify Group policy settings (cmd)

## Technique Context

T1484.001 (Group Policy Modification) covers adversary abuse of Group Policy Objects to disable
security controls, weaken defenses, or facilitate ransomware deployment across a domain. This
specific test replicates the LockBit Black ransomware's group policy modification behavior:
writing registry keys under `HKLM\SOFTWARE\Policies\Microsoft\Windows\System` to disable Group
Policy refresh timing and Windows SmartScreen. These modifications would take effect on all
machines that receive the GPO, making this technique particularly effective for domain-wide
ransomware deployment. This test uses `reg.exe` (the command-line registry editor) to write the
keys — the cmd variant of the two test cases for this technique.

## What This Dataset Contains

This dataset captures telemetry from six sequential `reg.exe` invocations on ACME-WS02, all
executed successfully.

**Security channel (4688/4689)** provides comprehensive coverage. Six distinct 4688 events record
individual reg.exe commands writing the following values to
`HKLM\SOFTWARE\Policies\Microsoft\Windows\System`:
- `GroupPolicyRefreshTimeDC` = 0 (disables DC GPO refresh interval)
- `GroupPolicyRefreshTimeOffsetDC` = 0 (disables DC GPO refresh offset)
- `GroupPolicyRefreshTime` = 0 (disables workstation GPO refresh interval)
- `GroupPolicyRefreshTimeOffset` = 0 (disables workstation GPO refresh offset)
- `EnableSmartScreen` = 0 (disables Windows SmartScreen)
- `ShellSmartScreenLevel` = Block (sets SmartScreen action to block — overridden by the disable above)

All six reg.exe processes exit with `0x0` — every modification **succeeded**. This is a clean
successful execution with no Defender intervention.

**Sysmon channel** (41 events, IDs 1, 7, 10, 11, 17) includes ProcessCreate events for each
reg.exe invocation (captured by the include-mode rules) with full command lines and hashes.
Sysmon ID 11 (FileCreate) may reflect registry hive file writes, and ID 17 (PipeCreate) captures
test framework pipe activity.

**PowerShell channel** (34 events, IDs 4103/4104) contains ART test framework boilerplate only. The
reg.exe invocations are not PowerShell operations.

## What This Dataset Does Not Contain

- Registry modification audit events (Security policy change auditing is set to `none` in this
  environment — 4657/4663 registry audit events are not present)
- Actual Group Policy replication or enforcement events
- Evidence of whether the modified keys persisted after test cleanup

## Assessment

This dataset represents a **fully successful execution** of LockBit Black's group policy weakening
sequence. All six registry writes completed without Defender intervention — Defender does not block
direct registry modification via reg.exe for these particular keys. The Security 4688 command lines
contain the complete picture: registry path, value name, type, and data for each write. This is
high-fidelity simulation telemetry with clear detection opportunities.

## Detection Opportunities Present in This Data

- **Security 4688**: `reg.exe` writing to `HKLM\SOFTWARE\Policies\Microsoft\Windows\System` with
  value names `GroupPolicyRefreshTime*` or `EnableSmartScreen` is the primary indicator; the
  specific LockBit key set is documented in threat intelligence
- **Security 4688**: Six reg.exe invocations in rapid succession from a PowerShell parent process,
  all writing to the same registry path, indicates scripted group policy weakening
- **Sysmon ID 1**: reg.exe spawned by powershell.exe (via cmd.exe) with `add
  HKLM\SOFTWARE\Policies\...` arguments; full command lines with all parameters visible
- **Behavioral sequence**: The complete six-key sequence (`GroupPolicyRefreshTimeDC`,
  `GroupPolicyRefreshTimeOffsetDC`, `GroupPolicyRefreshTime`, `GroupPolicyRefreshTimeOffset`,
  `EnableSmartScreen`, `ShellSmartScreenLevel`) matches published LockBit Black IOCs and can
  anchor a high-confidence behavioral detection
