# T1562.004-2: Disable or Modify System Firewall — Disable Microsoft Defender Firewall via Registry

## Technique Context

T1562.004 covers firewall disablement or modification. Test 2 achieves the same outcome as test 1
but bypasses the netsh abstraction layer entirely, writing directly to the firewall policy
registry keys using `reg.exe`. The command targets the PublicProfile:

```
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\
FirewallPolicy\PublicProfile" /v EnableFirewall /t REG_DWORD /d 0 /f
```

Direct registry writes to firewall policy keys bypass any API-level hooks that might intercept
netsh calls, making them somewhat stealthier than test 1's approach. Ransomware operators
frequently use this pattern.

## What This Dataset Contains

**Sysmon (38 events):** Sysmon ID 1 captures the attack chain:

- `whoami.exe` — ART test framework identity check (RuleName: T1033)
- `cmd.exe /c reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /v EnableFirewall /t REG_DWORD /d 0 /f` (RuleName: T1083)
- `reg.exe reg add ... /v EnableFirewall /t REG_DWORD /d 0 /f` (RuleName: T1083)

Sysmon ID 13 records the write directly from reg.exe:
- `TargetObject: HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\EnableFirewall`
- `Details: DWORD (0x00000000)`
- Writer: `reg.exe` (SYSTEM) — distinct from test 1 where svchost wrote via netsh's API

Unlike test 1, no Sysmon 12 (registry key create/delete) events appear, because reg.exe writes
directly without creating new keys. Sysmon 7 (image loads), 10 (process access), 11 (file
create), and 17 (named pipe) document the PowerShell test framework lifecycle.

**Security (13 events):** 4688/4689 for PowerShell, cmd.exe, reg.exe. Token adjustment (4703).
No SYSTEM logon cluster — running under the existing SYSTEM session. The 4688 for reg.exe
includes the full command line with the registry path and EnableFirewall value.

**PowerShell (36 events):** ART test framework boilerplate only — `Set-ExecutionPolicy Bypass` and
error-handling fragments. The attack uses cmd.exe/reg.exe; no technique-specific PowerShell
events appear.

## What This Dataset Does Not Contain (and Why)

**No Windows Firewall Operational log events.** The collection does not include
`Microsoft-Windows-Windows Firewall With Advanced Security/Firewall`. Unlike test 1 (where
netsh's API triggers firewall service events), a direct registry write may not generate
Windows Firewall change events until the service polls the registry.

**Only PublicProfile targeted.** Test 2 writes only to `PublicProfile`. DomainProfile and
StandardProfile remain at their prior values. A defender checking only DomainProfile might miss
this change.

**No immediate service notification.** The registry write does not force a service notification;
the firewall service may not apply the change until it next reads the registry.

**Sysmon-modular include filtering:** reg.exe is captured because it matches LOLBin rules; the
cmd.exe wrapper is also captured.

## Assessment

The test completed successfully. The direct registry write from reg.exe to `EnableFirewall=0`
is clearly documented in both Sysmon 13 and Security 4688. The contrast with test 1 is
instructive: the Sysmon 13 writer here is reg.exe (SYSTEM) rather than svchost, and no Sysmon
12 events appear. Defenders should test their detection logic against both the netsh-mediated
and direct registry variants.

## Detection Opportunities Present in This Data

- **Sysmon 13:** `EnableFirewall` written to 0 in any `FirewallPolicy\*Profile` key — this is
  the definitive indicator regardless of execution mechanism.
- **Sysmon 1 / Security 4688:** `reg.exe` or `reg add` with `SharedAccess\Parameters\
  FirewallPolicy` and `/v EnableFirewall /d 0` — highly specific.
- **Process lineage:** PowerShell → cmd.exe → reg.exe targeting firewall policy keys is not a
  legitimate administrative pattern on an end-user workstation.
- **Profile coverage:** Detection rules should cover all three profile paths (DomainProfile,
  StandardProfile, PublicProfile) — attackers may target any or all.
- **Comparison with test 1:** In test 1, Sysmon 13 shows svchost as the writer; here reg.exe
  is the writer. Rules that filter by writer process may miss one variant or the other.
