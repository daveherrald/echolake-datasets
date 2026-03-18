# T1562.004-22: Blackbit — Disable Windows Firewall Using netsh firewall

## Technique Context

T1562.004 covers firewall disablement. Test 22 emulates the technique used by the Blackbit
ransomware group, which uses the legacy `netsh firewall` syntax rather than the modern
`netsh advfirewall` syntax used in test 1. The command:

```
netsh firewall set opmode mode=disable
```

This syntax has been deprecated since Windows Vista in favor of `netsh advfirewall`, but it
remains functional on all modern Windows versions and continues to appear in ransomware toolkits.
Using legacy syntax can evade detection rules written specifically for `advfirewall`.

## What This Dataset Contains

**Sysmon (87 events):** The largest Sysmon count in this group. Sysmon ID 1 captures:

- `whoami.exe` (RuleName: T1033)
- `cmd.exe /c netsh firewall set opmode mode=disable` (RuleName: T1059.003)
- `netsh.exe firewall set opmode mode=disable` (RuleName: T1518.001)

Sysmon ID 13 records the downstream registry writes from the Windows Firewall service (svchost)
applying the change:
- `HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\EnableFirewall`  — `DWORD (0x00000000)`
- `HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\DoNotAllowExceptions` — `DWORD (0x00000000)`

Unlike test 2 (where reg.exe was the writer), here svchost writes the values after processing
the netsh API call — matching the pattern in test 1. Sysmon 12 (registry key operations), 7
(image loads), 10 (process access), 11 (file create), and 17 (named pipe) events are all present,
producing a rich but realistic event stream.

**Security (12 events):** 4688/4689 for whoami, cmd.exe, netsh.exe. Token adjustment (4703).
The 4688 for netsh includes the full command line with `firewall set opmode mode=disable`.

**PowerShell (34 events):** ART test framework boilerplate only — no technique-specific cmdlets.

## What This Dataset Does Not Contain (and Why)

**No Windows Firewall Operational events.** As in test 1, the `Microsoft-Windows-Windows Firewall
With Advanced Security/Firewall` channel is not collected. Events such as ID 2003 (firewall
settings changed) and ID 2006 would appear there.

**No PrivateProfile or StandardProfile writes in this dataset.** The legacy `set opmode` command
affects the current active profile and its associated keys; the exact set of registry keys
written depends on which profile is active at collection time.

**No pre/post firewall state comparison.** The dataset captures the disable action but not any
confirmation query or network exposure consequence.

## Assessment

The test completed successfully. The deprecated `netsh firewall set opmode mode=disable` command
is clearly captured in both Sysmon 1 and Security 4688, and the downstream `EnableFirewall=0`
registry writes from svchost are visible in Sysmon 13. This dataset is valuable precisely because
it demonstrates the legacy syntax variant — many detection rules target `advfirewall` and miss
this form.

## Detection Opportunities Present in This Data

- **Sysmon 1 / Security 4688:** `netsh.exe` with `firewall set opmode mode=disable` — the legacy
  syntax form that may evade `advfirewall`-specific rules.
- **Sysmon 13:** `EnableFirewall` written to 0 in `FirewallPolicy\DomainProfile` by svchost —
  same downstream indicator as test 1, confirming that registry-based detection catches both
  `advfirewall` and legacy `firewall` forms.
- **Sysmon 1:** Both `advfirewall set currentprofile state off` (test 1) and `firewall set opmode
  mode=disable` (test 22) should appear in detection signatures — legacy syntax is actively used
  by Blackbit and other ransomware families.
- **Process lineage:** PowerShell → cmd.exe → netsh.exe on an end-user workstation is anomalous
  regardless of the specific netsh subcommand.
- **Sysmon 12:** Registry key operations on `SharedAccess\Parameters\FirewallPolicy` from
  svchost immediately following a netsh invocation are a reliable correlation anchor.
