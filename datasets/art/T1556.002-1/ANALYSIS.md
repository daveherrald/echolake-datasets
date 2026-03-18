# T1556.002-1: Password Filter DLL — Install and Register Password Filter DLL

## Technique Context

T1556.002 (Password Filter DLL) is a persistence and credential access technique where an attacker registers a malicious DLL as a Windows password notification filter. The LSA (Local Security Authority) loads registered notification packages from `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages` at boot. Any DLL listed there receives plaintext passwords during every password change operation. This is a powerful long-term credential harvesting mechanism targeting the password change workflow rather than cached credentials.

## What This Dataset Contains

The dataset spans approximately two minutes on 2026-03-14 on ACME-WS02 (Windows 11 Enterprise, domain acme.local). The test registered an ART-provided DLL (`AtomicRedTeamPWFilter.dll`) as a notification package. The EID 4104 script block records the full sequence:

```powershell
reg.exe export HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ "C:\AtomicRedTeam\atomics\T1556.002\lsa_backup.reg"
$passwordFilterName = (Copy-Item "C:\AtomicRedTeam\atomics\T1556.002\bin\AtomicRedTeamPWFilter.dll" \
    -Destination "C:\Windows\System32" -PassThru).basename
$lsaKey = Get-Item "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"
$notificationPackagesValues = $lsaKey.GetValue("Notification Packages")
$notificationPackagesValues += $passwordFilterName
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" "Notification Packages" $notificationPackagesValues
```

This script: backs up the LSA registry hive, copies the DLL to `System32`, reads the existing `Notification Packages` value, appends the new DLL name, and writes it back.

Sysmon events include:
- **EID 1**: `whoami.exe` (T1033), `powershell.exe` (T1083 — triggered by the `-PassThru` copy), and `reg.exe` (T1083 — registry export)
- **EID 7**: DLL loads into PowerShell instances
- **EID 10**: Cross-process PowerShell access (T1055.001)
- **EID 11**: PowerShell transcript files; notably also a file creation at `00:46:38` (near end of test window) consistent with test cleanup/restore
- **EID 17**: Named PSHost pipes

Security events: EID 4688/4689/4703 covering process lifecycle and token adjustment.

System EID 7040: BITS service start type changed (environment background noise). WMI EID 5858: Failed WMI query for `wsmprovhost.exe` (ART test framework infrastructure).

The two-minute duration (vs. six seconds for other tests) reflects a cleanup phase where the test restores the original LSA registry backup after registration.

## What This Dataset Does Not Contain (and Why)

**No Sysmon EID 13 (Registry value set).** The `Set-ItemProperty` call modified `HKLM\...\Notification Packages` but the Sysmon configuration did not match this key path with a registry monitoring rule that would produce EID 13. Registry modification events in sysmon-modular typically require explicit key rules.

**No Security EID 4657 (registry modification).** Registry object access auditing is not enabled (`policy_change: none`).

**No DLL load event for AtomicRedTeamPWFilter.dll.** LSA loads notification package DLLs at next boot; the test registered the DLL but did not trigger a password change to verify DLL invocation. The EID 7 (ImageLoad) events observed are for PowerShell's own DLL loads.

**No LSASS access telemetry.** The DLL registration modifies a registry key — it does not directly touch the LSASS process during registration.

## Assessment

The primary forensic value is in EID 4104, which exposes the complete registration logic including the exact DLL name and the target registry key. The `reg.exe` backup of the LSA hive (captured in EID 1) is both a defense preparation step and an indicator — attackers often backup before modifying sensitive keys. The two-minute window captures both registration and cleanup, making the dataset representative of a full test lifecycle.

## Detection Opportunities Present in This Data

- **EID 4104**: Script block explicitly names `AtomicRedTeamPWFilter.dll` and `Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" "Notification Packages"` — the registry key modification is fully visible in script block logging.
- **EID 1 (Sysmon)**: `reg.exe` spawned from PowerShell under SYSTEM exporting `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\` is a specific and detectable pre-attack backup pattern.
- **EID 4688 (Security)**: `reg.exe` with LSA key export in the command line is a reliable indicator when command-line logging is enabled.
- **Registry monitoring**: Any write to `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages` that adds an unexpected DLL name is a high-fidelity detection. Enabling Sysmon EID 13 for this key path would capture it directly.
- **File system**: `Copy-Item` writing an unexpected DLL to `C:\Windows\System32` from a non-installer process is detectable with file integrity monitoring.
