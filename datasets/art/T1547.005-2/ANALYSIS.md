# T1547.005-2: Security Support Provider — Security Support Provider - Modify HKLM Lsa OSConfig Security Packages

## Technique Context

T1547.005 (Security Support Provider) enables persistence by registering a DLL as a Security Support Provider that LSASS loads at boot. Test 2 targets the `OSConfig` subkey — `HKLM\System\CurrentControlSet\Control\Lsa\OSConfig\Security Packages` — rather than the primary `Lsa` key tested in T1547.005-1. The `OSConfig` key is less commonly monitored than the parent `Lsa` key and is used by some real-world adversaries specifically to evade detections that only watch the primary path. Both keys are read by LSASS during initialization, making either a viable persistence vector.

## What This Dataset Contains

The test modifies the `Security Packages` multi-string value under `HKLM\System\CurrentControlSet\Control\Lsa\OSConfig` to insert `AtomicTest.dll`. Notably, **no Sysmon EID 13 events were captured** for this test — the sysmon-modular configuration does not include a rule covering the OSConfig subkey. This is a meaningful gap in the dataset.

The PowerShell EID 4104 script block confirms the operation in full:

```powershell
$oldvalue = $(Get-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa\OSConfig
  -Name 'Security Packages' | Select-Object -ExpandProperty 'Security Packages');
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\OSConfig"
  -Name 'Security Packages old' -Value "$oldvalue";
$newvalue = "AtomicTest.dll";
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig
  -Name 'Security Packages' -Value $newvalue
```

Sysmon event coverage consists of 26 events: EID 7 (image loads, 17 events), EID 17 (pipe events, 2), EID 10 (process access, 2), EID 11 (file creates, 3), and EID 1 (process create, 2). The EID 1 entries capture `whoami.exe` (tagged T1033) and the PowerShell process itself (tagged T1083). There are no EID 13 events.

Security EID 4688 records process creation for `whoami.exe` and the PowerShell process with its full command line. Security EID 4703 records privilege adjustment for the SYSTEM token. Ten security events total (4688 × 2, 4689 × 7, 4703 × 1).

The PowerShell log (56 events) is dominated by test framework boilerplate — the ~52 formatter blocks — with 2 substantive EID 4104 entries containing the attack script block.

## What This Dataset Does Not Contain

**Sysmon EID 13 is entirely absent.** The sysmon-modular configuration captures writes to the parent `Lsa` key (seen in T1547.005-1) but does not have a rule matching the `OSConfig` subkey. This demonstrates a real detection gap that adversaries can exploit: modifying the OSConfig path avoids the most common Sysmon-based detection for this technique.

**LSASS DLL loading** is not captured — the DLL would only load at the next boot, outside this window.

**No Security EID 4657** (registry modification) — object access auditing is disabled.

**Registry write confirmation** from Sysmon is unavailable; detection relies entirely on PowerShell script block logging in this dataset.

## Assessment

The test ran to completion. The modification is confirmed only through PowerShell EID 4104 script block logging — the primary detection telemetry source for this variant. The absence of Sysmon EID 13 is itself a significant finding: the OSConfig subkey path evades the Sysmon registry monitoring rules that would have fired for the parent Lsa path. This dataset is valuable precisely because it illustrates the difference in coverage between the two T1547.005 test variants.

## Detection Opportunities Present in This Data

- **PowerShell EID 4104**: The script block captures the full `OSConfig` path and the inserted DLL name. This is the only reliable detection source in this dataset. Alerting on `Set-ItemProperty` targeting `Lsa\OSConfig` with `Security Packages` is effective.
- **Absence of Sysmon EID 13**: Detection engineers should note that the sysmon-modular configuration as deployed does not generate registry write events for the OSConfig subkey. Expanding the Sysmon registry monitoring ruleset to cover `Control\Lsa\OSConfig\Security Packages` would close this gap.
- **Security EID 4688**: The PowerShell command line includes the full `HKLM:\System\CurrentControlSet\Control\Lsa\OSConfig` path, providing a detection anchor in process creation logs.
- **Behavioral sequence**: `whoami.exe` immediately preceding a PowerShell process targeting LSA registry keys is a reliable correlation pair regardless of which subkey is modified.
