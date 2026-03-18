# T1490-11: Inhibit System Recovery — Modify VSS Service Permissions

## Technique Context

MITRE ATT&CK T1490 (Inhibit System Recovery) includes manipulation of the Volume Shadow Copy Service's security descriptor to prevent other processes from accessing or restoring shadows. This test uses `sc sdset VSS D:(D;;GA;;;NU)(D;;GA;;;WD)(D;;GA;;;AN)S:(AU;FA;GA;;;WD)(AU;OIIOFA;GA;;;WD)` to replace the VSS service's DACL with entries that deny `GA` (Generic All) to `NU` (Network), `WD` (Everyone), and `AN` (Anonymous). This effectively locks all users and processes out of the VSS service — neither administrators nor backup agents can create or access shadow copies while this DACL is in place. This technique is less commonly documented than VSC deletion but is potentially more persistent: the service remains installed but inaccessible, causing any backup or restore operation that contacts VSS to fail silently or with an access error.

## What This Dataset Contains

**Sysmon (Event ID 1) — ProcessCreate:**
The chain `cmd.exe /c sc sdset VSS D:(D;;GA;;;NU)(D;;GA;;;WD)(D;;GA;;;AN)...` → `sc.exe sdset VSS D:(D;;GA;;;NU)...` is fully captured. The `cmd.exe` parent is tagged `technique_id=T1059.003` and `sc.exe` is tagged `technique_id=T1543.003,technique_name=Windows Service`. Both run as `NT AUTHORITY\SYSTEM` from `C:\Windows\TEMP\`. The full DACL string is present in the command line in both events.

**Security (Event IDs 4688/4689/4703):**
`whoami.exe`, `cmd.exe`, and `sc.exe` create/exit events are all present. `sc.exe` exits with `0x0` (success) — the DACL modification was applied. Token right adjustment (4703) for `sc.exe` reflects privilege use during service modification.

**Sysmon (Event ID 13) — RegistryEvent:**
`HKLM\System\CurrentControlSet\Services\VSS\Security\Security` is written as binary data by `services.exe` (PID 740). This is the service security descriptor being updated in the registry — the direct artifact of the `sc sdset` operation. Sysmon misclassifies this with the rule `technique_id=T1003.002,technique_name=Security Account Manager` (because of the `Security` key path pattern), which is a false rule match, but the event itself is valuable regardless of the rule tag.

**PowerShell channel:** Contains only `Set-StrictMode` and `Set-ExecutionPolicy -Bypass` test framework boilerplate. No technique content — the `sc sdset` operation runs through `cmd.exe`, not PowerShell.

## What This Dataset Does Not Contain

- **No Security channel events** confirming the DACL change was applied (e.g., EID 4670 — permissions on an object were changed). Object access auditing is `none` in this environment, so no service object security change events are generated.
- **No subsequent VSS access failure events.** The dataset does not include attempts to use VSS after the DACL change, which would show how the modification manifests to backup software.
- **No System log service control events** reflecting the security descriptor change on the VSS service.
- **No WMI or Application log backup service errors** resulting from the locked-out VSS.

## Assessment

This is a clean, compact dataset that captures the technique across three independent sources (Sysmon EID 1, Security EID 4688, Sysmon EID 13). The registry event for `HKLM\...\Services\VSS\Security\Security` is particularly useful — it is a direct artifact of the service ACL modification that does not depend on monitoring `sc.exe`. The Sysmon rule mislabeling the registry event as T1003.002 is a quirk of the sysmon-modular configuration's regex matching on the key name. Detection engineers should note that the DACL string itself (`D:(D;;GA;;;NU)(D;;GA;;;WD)(D;;GA;;;AN)`) is a reliable signature: legitimate service hardening does not deny `GA` to `WD` (Everyone). The technique is low-noise and the `sc sdset VSS` pattern has essentially no benign administrative equivalent.

## Detection Opportunities Present in This Data

1. **Sysmon EID 1 — `sc.exe sdset VSS` with a deny DACL** — the combination of `sdset`, the VSS service name, and `D;;GA` (deny Generic All) entries is unambiguous; Sysmon tags the sc.exe event as T1543.003.
2. **Security EID 4688 — `sc sdset VSS D:(D;;GA;;;WD)...` command line** — the full DACL string is captured; a substring match on `sdset VSS` combined with a deny ACE (`D;;`) flags the malicious intent.
3. **Sysmon EID 13 — write to `HKLM\System\CurrentControlSet\Services\VSS\Security\Security`** — a registry-based detection that fires even if the sc.exe command line is obscured or the operation is performed via another path.
4. **`D;;GA;;;WD` (deny Generic All to Everyone) in a service SDDL string** — this is a rare and hostile ACE that has no legitimate administrative justification in the VSS service descriptor.
5. **`sc.exe` launched by `cmd.exe` from `C:\Windows\TEMP\` as SYSTEM** — execution context narrows to the attacker scenario and reduces false positives from legitimate service management.
