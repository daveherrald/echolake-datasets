# T1547.008-1: LSASS Driver — LSASS Driver - Modify Registry to Load Arbitrary DLL via LsaDbExtPt

## Technique Context

T1547.008 (LSASS Driver) covers adversary persistence through the Windows LSASS process by registering a DLL as an LSASS extension. The `LsaDbExtPt` registry value under `HKLM\System\CurrentControlSet\Services\NTDS` is a legitimate extension point intended for Active Directory authentication providers. By pointing this value to a malicious DLL, an attacker ensures their code is loaded by LSASS at startup, running in a highly privileged context with direct access to authentication credentials. This technique has appeared in APT campaigns targeting domain controllers.

## What This Dataset Contains

The test sets the `LsaDbExtPt` registry value to point to a DLL from the ART ExternalPayloads directory. A Sysmon EID 13 (RegistryEvent - Value Set) captures the write:

```
Registry value set:
  EventType: SetValue
  Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
  TargetObject: HKLM\System\CurrentControlSet\Services\NTDS\LsaDbExtPt
  Details: C:\AtomicRedTeam\atomics\..\ExternalPayloads\lsass_lib.dll
  User: NT AUTHORITY\SYSTEM
```

The RuleName field shows `-`, meaning the sysmon-modular configuration does not have a specific rule tagging this key path as T1547.008. The write is still captured because the registry monitoring configuration covers the NTDS services key.

The PowerShell EID 4104 script block is captured in full:

```powershell
& {New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\NTDS
  -Name LsaDbExtPt
  -Value "C:\AtomicRedTeam\atomics\..\ExternalPayloads\lsass_lib.dll"}
```

Sysmon event counts: 37 events across EID 1 (2), EID 7 (26), EID 10 (2), EID 11 (3), EID 13 (1), EID 17 (3). The 26 EID 7 events are DLL image loads — legitimate system DLLs loaded by the PowerShell process. The two EID 1 entries capture `whoami.exe` (T1033) and the child PowerShell process (T1083).

Security events: 10 events (4688 × 2, 4689 × 7, 4703 × 1). The EID 4688 for the PowerShell process shows the full command line including the `LsaDbExtPt` key name.

The PowerShell log contains 37 events, predominantly test framework boilerplate, with 2 substantive EID 4104 entries.

## What This Dataset Does Not Contain

**The referenced DLL (`lsass_lib.dll`) is a placeholder path.** The `ExternalPayloads` directory may not exist on the test host. If the DLL does not exist on disk, LSASS will fail to load it at the next boot — but the registry modification still represents a persistence attempt.

**LSASS DLL loading** is not captured — the extension DLL is only loaded by LSASS at system startup, which does not occur during this test window. No Sysmon EID 7 for `lsass_lib.dll` is present.

**Sysmon EID 12 (key create)** is absent — `LsaDbExtPt` is a new value being created under an existing key; Sysmon captures the value set (EID 13) but not a key creation in this case.

**Windows Defender** was active but did not block the registry modification. A real malicious DLL would likely be detected when written to disk, but the registry write itself is not blocked.

**No Security EID 4657** — object access auditing is disabled.

## Assessment

The test ran to completion. The registry modification is confirmed by Sysmon EID 13 and the PowerShell script block. The dataset captures the persistence registration phase — the adversary's foothold in the registry — before any payload execution. The absence of a T1547.008 rule tag in Sysmon EID 13 is a detection coverage gap: detections for this technique must rely on the registry path string matching rather than a pre-applied Sysmon rule label.

## Detection Opportunities Present in This Data

- **Sysmon EID 13**: A write to `HKLM\System\CurrentControlSet\Services\NTDS\LsaDbExtPt` is extremely rare in legitimate operation and should trigger an alert. The registry path is specific enough for a high-confidence, low-false-positive rule.
- **PowerShell EID 4104**: The `New-ItemProperty` cmdlet targeting `Services\NTDS` with `LsaDbExtPt` is fully captured in the script block. The DLL path is also visible.
- **Security EID 4688**: The PowerShell command line includes both the key path and the value name, providing detection from process creation auditing without Sysmon.
- **Path traversal indicator**: The DLL path `C:\AtomicRedTeam\atomics\..\ExternalPayloads\lsass_lib.dll` contains `..` path traversal — an artifact of how ART constructs payload paths that may aid in detecting ART-generated test traffic specifically.
- The `Services\NTDS` key is only legitimately modified during Active Directory Domain Services installation or configuration changes. Any modification by a user-space process outside of those contexts is anomalous.
