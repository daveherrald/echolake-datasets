# T1562.004-20: LockBit Black — Unusual Windows Firewall Registry Modification (cmd)

## Technique Context

T1562.004 covers firewall disablement. Test 20 emulates the firewall-disabling behavior observed
in LockBit Black (LockBit 3.0) ransomware. Rather than targeting the
`SharedAccess\Parameters\FirewallPolicy` service keys directly (tests 1 and 2), it writes to
the Group Policy–enforced firewall policy path:

```
HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile  /v EnableFirewall /t REG_DWORD /d 0
HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile /v EnableFirewall /t REG_DWORD /d 0
```

Group Policy firewall settings take precedence over local firewall settings, and writing to this
path is characteristic of LockBit 3.0's pre-encryption defense impairment phase. The execution
uses a cmd.exe wrapper invoking two sequential reg.exe commands, exactly as documented in LockBit
Black incident reports.

## What This Dataset Contains

**Sysmon (28 events):** Sysmon ID 1 captures the full execution chain:

- `whoami.exe` (RuleName: T1033) — identity check
- `cmd.exe /c reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v EnableFirewall /t REG_DWORD /d 0 /f & reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" /v EnableFirewall /t REG_DWORD /d 0 /f` (RuleName: T1059.003)
- Two separate `reg.exe` invocations — one for each profile — both tagged T1012 (Query Registry)

The two reg.exe processes are captured individually in Sysmon 1, enabling per-profile analysis.
Sysmon 7 (image loads), 10 (process access), 11 (file create), and 17 (named pipe) events
document the PowerShell test framework lifecycle. No Sysmon 13 (registry value set) events appear for
the Group Policy firewall path — the sysmon-modular rules do not include
`SOFTWARE\Policies\Microsoft\WindowsFirewall` in their registry monitoring targets.

**Security (14 events):** 4688/4689 for whoami, cmd.exe, both reg.exe instances. Token
adjustment (4703). The 4688 events include full command lines, showing both `/DomainProfile` and
`/StandardProfile` targets explicitly.

**PowerShell (34 events):** ART test framework boilerplate only — the attack uses cmd/reg, no
technique-specific PowerShell cmdlet invocations.

## What This Dataset Does Not Contain (and Why)

**No Sysmon 13 for the Group Policy firewall keys.** The sysmon-modular configuration does not
monitor `HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall`. This is a detection gap: the
successful registry write is visible only via PowerShell command-line arguments (in Security 4688
or Sysmon 1), not via registry event monitoring.

**No Windows Firewall Operational events.** Group Policy firewall settings do not immediately
trigger Windows Firewall service change notifications; the Firewall log channel is also not
collected here.

**No PrivateProfile coverage.** LockBit Black targets DomainProfile and StandardProfile; some
variants also target PrivateProfile, which is not in this test.

## Assessment

The test completed successfully. Both reg.exe invocations are captured with full command lines in
Sysmon 1 and Security 4688. The LockBit-specific pattern of dual-profile Group Policy path
targeting via a single chained cmd.exe command is clearly documented. The absence of Sysmon 13
for this path is a meaningful gap for defenders — registry event monitoring must explicitly cover
`SOFTWARE\Policies\Microsoft\WindowsFirewall`.

## Detection Opportunities Present in This Data

- **Sysmon 1 / Security 4688:** `reg.exe` writing `EnableFirewall=0` to
  `HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\*Profile` — the LockBit Group Policy path
  is a highly specific, reliable indicator.
- **Sysmon 1:** cmd.exe with chained `reg add ... & reg add ...` targeting both DomainProfile and
  StandardProfile in a single command — the dual-profile pattern is characteristic of LockBit
  Black.
- **Process lineage:** PowerShell → cmd.exe → two sequential reg.exe processes within one second
  — the timing and lineage together are distinctive.
- **Registry monitoring gap:** Defenders should add `HKLM\SOFTWARE\Policies\Microsoft\
  WindowsFirewall` to Sysmon registry event rules or equivalent EDR coverage.
- **Correlation with ransomware TTPs:** This pattern, combined with other LockBit-associated
  behaviors (shadow copy deletion, AV/EDR disablement), provides high-confidence ransomware
  pre-encryption indicators.
