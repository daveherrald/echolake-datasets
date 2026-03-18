# T1562.004-5: Disable or Modify System Firewall — Open a Local Port Through Windows Firewall to Any Profile

## Technique Context

T1562.004 (Disable or Modify System Firewall) includes modifications that allow inbound traffic
across all firewall profiles (Domain, Private, Public). Most legitimate application rules are
profile-specific. Specifying `profile=any` or targeting all three profiles removes the safety net
that would normally keep public-network traffic blocked even if domain or private rules are
permissive. This is particularly significant for RDP (port 3389), which should only be reachable
on managed network segments.

## What This Dataset Contains

The test ran `netsh advfirewall firewall add rule name="Open Port to Any" dir=in protocol=tcp
localport=3389 action=allow profile=any` via PowerShell (which invoked netsh.exe directly).
Executed under NT AUTHORITY\SYSTEM.

**Sysmon EID 1 — process creation (50 events, 3 process-create):**
- `powershell.exe & {netsh advfirewall firewall add rule name="Open Port to Any" dir=in protocol=tcp localport=3389 action=allow profile=any}` (parent: WmiPrvSE.exe)
- `netsh.exe advfirewall firewall add rule "name=Open Port to Any" dir=in protocol=tcp localport=3389 action=allow profile=any` (child of powershell.exe)
- Preceded by `whoami.exe`

**Sysmon EID 13 — registry value set (2 events):**
The Firewall service wrote the new rule:
- `HKLM\...\FirewallRules\{A521DD73-7838-4958-B953-1895889ACF9C}` — `v2.32|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=3389|Name=Open Port to Any|`
- `Epoch\Epoch` counter increment

**Security EID 4688 (12 events):** whoami.exe, powershell.exe, netsh.exe. All under SYSTEM,
Token Elevation Type 1.

**PowerShell EID 4104 (38 events):** Two script blocks contain test-specific content:
```
& {netsh advfirewall firewall add rule name="Open Port to Any" dir=in protocol=tcp localport=3389 action=allow profile=any}
```
and an unwrapped version. The remaining 36 blocks are ART test framework boilerplate.

## What This Dataset Does Not Contain (and Why)

**Windows Firewall audit events:** `policy_change: none` in the audit policy configuration means
no EID 2004 (rule added) or 2005 (rule modified) events from the Windows Firewall provider were
generated.

**No network events:** The firewall rule is created but no connections are initiated or received
during this test window.

**The `profile=any` flag is not reflected in the Sysmon EID 13 Details field** in the way one
might expect. The rule is written with `Active=TRUE` and `Dir=In` but the profile constraint
(or absence thereof) in the rule string would need to be parsed from the raw registry value to
confirm all-profile scope.

## Assessment

This dataset demonstrates the `netsh advfirewall` add-rule pattern with two notable
characteristics: port 3389 (RDP) and the `profile=any` modifier. The PowerShell EID 4104 events
are uniquely valuable here because PowerShell invoked netsh directly, meaning the full command
appears in script block logging — a different execution path from the cmd.exe-via-PowerShell
approach seen in other tests. The Sysmon EID 13 registry write confirming the rule creation
completes the picture. Test executed successfully.

## Detection Opportunities Present in This Data

- **PowerShell EID 4104:** Script block containing `netsh advfirewall firewall add rule` with `profile=any` — this string combination is highly anomalous
- **Sysmon EID 1:** `netsh.exe` with `advfirewall firewall add rule` targeting `localport=3389` with `profile=any`
- **Sysmon EID 1:** `netsh.exe` spawned from `powershell.exe` (not cmd.exe) with firewall modification arguments
- **Sysmon EID 13:** New `FirewallRules\{GUID}` written for `LPort=3389` by svchost.exe/mpssvc — especially suspicious if the rule name is generic
- **Security EID 4688:** netsh.exe process creation with command-line logging showing `profile=any` with `localport=3389`
- **Baseline deviation:** Any RDP inbound rule created with `profile=any` (or without a profile restriction) is almost never legitimate on a workstation
