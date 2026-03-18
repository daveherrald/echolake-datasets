# T1556.002-2: Password Filter DLL — Install Additional Authentication Packages

## Technique Context

T1556.002 (Password Filter DLL) has a second registration vector: the `Authentication Packages` value under `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\`. Unlike `Notification Packages` (which receive plaintext passwords during changes), Authentication Packages are loaded by LSASS at boot and participate in the actual authentication process. Registering a malicious DLL here enables interception of authentication attempts — a more privileged and persistent credential access mechanism. This test demonstrates registration of the same `AtomicRedTeamPWFilter.dll` under the `Authentication Packages` value rather than `Notification Packages`.

## What This Dataset Contains

The dataset spans approximately two minutes on 2026-03-14 on ACME-WS02. The EID 4104 script block records the complete action:

```powershell
reg.exe export HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ "C:\AtomicRedTeam\atomics\T1556.002\lsa_backup.reg"
$passwordFilterName = (Copy-Item "C:\AtomicRedTeam\atomics\T1556.002\bin\AtomicRedTeamPWFilter.dll" \
    -Destination "C:\Windows\System32" -PassThru).basename
$lsaKey = Get-Item "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"
$AuthenticationPackagesValues = $lsaKey.GetValue("Authentication Packages")
$AuthenticationPackagesValues += $passwordFilterName
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" "Authentication Packages" $AuthenticationPackagesValues
```

This dataset is more telemetry-rich than T1556.002-1. Security events include EID 4624 (Logon Type 5 — service logon), EID 4627 (group membership), EID 4672 (special privileges assigned to SYSTEM) — all generated during the boot-time or service-init activity triggered by the LSA change. The presence of logon events (absent in T1556.002-1) reflects the deeper authentication subsystem involvement.

Sysmon events add EID 13 (Registry value set) in this dataset — specifically a `svchost.exe` write to `HKLM\System\CurrentControlSet\Services\W32Time\Config\Status\LastGoodSampleInfo` (time sync background activity), not the LSA modification itself. Sysmon EID 3 (Network connection) captures `MsMpEng.exe` outbound connections tagged T1036 (Masquerading) — Windows Defender cloud lookups occurring during the test window.

System EID 7040: BITS service start type changed from demand to auto (cleanup/restore phase reversing the T1555.003-8 BITS change). WMI EID 5860: Temporary WMI subscription for `wsmprovhost.exe` monitoring.

## What This Dataset Does Not Contain (and Why)

**No Sysmon EID 13 for the LSA `Authentication Packages` key modification.** As with T1556.002-1, the sysmon-modular configuration does not include a rule targeting this specific registry path.

**No LSASS process modification events.** The DLL registration requires a reboot to take effect — LSASS does not reload authentication packages at runtime.

**No Security EID 4657 (registry modification).** Registry auditing is not enabled.

**No observable credential interception.** The test registered the DLL but did not reboot the system to activate it, so no authentication was intercepted.

## Assessment

The key difference from T1556.002-1 is the target registry value (`Authentication Packages` vs. `Notification Packages`) and the resulting authentication subsystem activity in the Security log. The appearance of EID 4624/4627/4672 in this dataset — absent in T1556.002-1 — reflects either a service account relogon or LSA activity triggered by modifying the authentication packages configuration. This makes T1556.002-2 slightly more detectable through Security log monitoring alone, as the logon events provide temporal correlation with the registry modification.

## Detection Opportunities Present in This Data

- **EID 4104**: Script block shows `Set-ItemProperty` targeting `"Authentication Packages"` at the LSA key — fully visible and directly signable.
- **EID 4688**: `reg.exe` spawned from PowerShell exporting the LSA hive is the same pre-attack backup indicator as T1556.002-1.
- **EID 4624/4627/4672**: Service logon (Type 5) with special privileges assigned to SYSTEM immediately following a PowerShell session is anomalous on a workstation and worth correlating with preceding process activity.
- **Registry monitoring**: `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Authentication Packages` additions are extremely rare in production and should generate high-priority alerts.
- **Sysmon EID 3**: The `MsMpEng.exe` network connections show Defender was active and scanning — confirming the test ran in a real protected environment. These are benign but confirm the collection environment's integrity.
