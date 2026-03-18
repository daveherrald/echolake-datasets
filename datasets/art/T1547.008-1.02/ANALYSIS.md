# T1547.008-1: LSASS Driver — Modify Registry to Load Arbitrary DLL via LsaDbExtPt

## Technique Context

T1547.008 (LSASS Driver) covers persistence through the Windows LSASS process by registering a DLL as an LSASS extension via a dedicated registry extension point. The `LsaDbExtPt` value under `HKLM\SYSTEM\CurrentControlSet\Services\NTDS` is an extension mechanism for Active Directory authentication providers. By writing a DLL path to this value, an attacker ensures their code is loaded by LSASS at system startup with SYSTEM-level privileges and direct access to the authentication credential pipeline. This technique is associated with APT campaigns targeting domain controllers, though it can be used on any domain-joined workstation — NTDS key access requires administrator privileges regardless.

This dataset captures the **undefended** execution of ART test T1547.008-1 on ACME-WS06 with Defender disabled. The defended variant (ACME-WS02) shows nearly identical counts: 37 sysmon, 10 security, 37 powershell. The undefended dataset shows 35 sysmon, 4 security, 98 powershell. Defender does not block this registry modification.

## What This Dataset Contains

The dataset spans approximately 5 seconds on ACME-WS06 and contains 137 events across three log sources.

**PowerShell EID 4104** captures the test payload:

```powershell
& {New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\NTDS
   -Name LsaDbExtPt
   -Value "C:\AtomicRedTeam\atomics\..\ExternalPayloads\lsass_lib.dll"}
```

The `New-ItemProperty` cmdlet creates the `LsaDbExtPt` value (it did not previously exist) and sets it to the DLL path. The `..` in the path indicates the ART ExternalPayloads directory relative to the atomics root.

**Sysmon (35 events, EIDs 1, 7, 10, 11, 13, 17):**

The dataset includes 1 EID 13 (RegistrySetValue) event. It captures the write performed by `powershell.exe` as SYSTEM:

```
EventType: SetValue
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
TargetObject: HKLM\System\CurrentControlSet\Services\NTDS\LsaDbExtPt
Details: C:\AtomicRedTeam\atomics\..\ExternalPayloads\lsass_lib.dll
User: NT AUTHORITY\SYSTEM
```

The `RuleName` field is `-` — no named rule in sysmon-modular targets the `NTDS\LsaDbExtPt` path specifically. The event is captured by a broad registry monitoring rule.

- **EID 1 (ProcessCreate):** Four events: `whoami.exe` (T1033, pre-check), the attack `powershell.exe` (T1083) with `New-ItemProperty` and `LsaDbExtPt` in the command line, a second `whoami.exe`, and the cleanup `powershell.exe` with `Remove-ItemProperty`.

- **EID 10 (ProcessAccess):** Four events tagged `T1055.001` — test framework handle acquisition.

- **EID 17 (PipeCreate):** Two named pipe creation events.

- **EID 11 (FileCreate):** One file create for a PowerShell profile data artifact.

- **EID 7 (ImageLoad):** 23 DLL load events for PowerShell instance initialization.

**Security (4 events, all EID 4688):** Process creation records for `whoami.exe` (twice) and both `powershell.exe` instances. The attack instance's 4688 record captures:

```
NewProcessName: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: "powershell.exe" & {New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\NTDS -Name LsaDbExtPt -Value "C:\AtomicRedTeam\atomics\..\ExternalPayloads\lsass_lib.dll"}
```

The cleanup PowerShell's 4688 records `Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS" -Name "LsaDbExtPt"`, documenting the restoration.

## What This Dataset Does Not Contain

**No LSASS DLL loading.** The `lsass_lib.dll` path points to the ART ExternalPayloads directory, which may not exist on this host, and regardless the DLL would only be loaded by LSASS at the next system boot. No Sysmon EID 7 event for `lsass_lib.dll` loading into `lsass.exe` is present.

**No Sysmon EID 12 (RegistryKeyCreate).** `LsaDbExtPt` is a new value being created under the existing `HKLM\SYSTEM\CurrentControlSet\Services\NTDS` key. Sysmon captures the value set (EID 13) without a corresponding key creation event since the key itself already exists.

**No named T1547.008 rule tag.** The sysmon-modular configuration does not have a specific include rule for the `NTDS\LsaDbExtPt` path. This is a coverage gap: the LSASS extension point is a known persistence mechanism that warrants explicit monitoring.

**No lsass.exe process telemetry.** No direct access to or modification of the `lsass.exe` process is present — the technique operates entirely through registry configuration, and the DLL loading would only occur at boot time.

## Assessment

This dataset documents a registry-only phase of the T1547.008 technique. The critical artifact is the Sysmon EID 13 event showing `HKLM\System\CurrentControlSet\Services\NTDS\LsaDbExtPt` being written with a DLL path by `powershell.exe`, confirmed independently by the Security EID 4688 command line.

The `LsaDbExtPt` value name is highly specific — it is not a commonly observed registry value in normal Windows operation. Its presence in a Sysmon EID 13 or PowerShell script block is a strong indicator of T1547.008 activity regardless of whether a named detection rule fires.

The gap between the defended and undefended datasets for this technique is minimal. Defender does not block this modification; the technique is equally executable in either environment. This underscores that detection must come from behavioral telemetry rather than endpoint protection.

## Detection Opportunities Present in This Data

- **Sysmon EID 13:** Any write to `HKLM\SYSTEM\CurrentControlSet\Services\NTDS\LsaDbExtPt`. This value has no legitimate purpose in normal Windows operation outside of Active Directory-integrated authentication providers. Any write to it is anomalous.

- **Sysmon EID 13, value path content:** The `Details` field shows the DLL path. A DLL path pointing to non-system locations (user temp directories, ART-style paths, external payloads directories) is immediately suspicious.

- **PowerShell EID 4104:** Script blocks containing `New-ItemProperty` or `Set-ItemProperty` targeting `HKLM:\SYSTEM\CurrentControlSet\Services\NTDS` with `LsaDbExtPt` as the `Name` parameter.

- **Security EID 4688:** `powershell.exe` command lines containing `LsaDbExtPt` or `NTDS` and `SYSTEM\CurrentControlSet\Services`. The value name `LsaDbExtPt` is unusual enough to be a reliable string match.

- **Registry baseline:** Including `HKLM\SYSTEM\CurrentControlSet\Services\NTDS\LsaDbExtPt` in periodic registry baseline comparisons would detect the addition of this value even in the absence of real-time write events.
