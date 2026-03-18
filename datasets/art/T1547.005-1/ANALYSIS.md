# T1547.005-1: Security Support Provider — Security Support Provider - Modify HKLM Lsa Security Packages

## Technique Context

T1547.005 (Security Support Provider) abuses the Windows Security Support Provider (SSP) architecture to load adversary-controlled DLLs into LSASS at boot. The `Security Packages` value under `HKLM\System\CurrentControlSet\Control\Lsa` lists SSP/AP DLLs that the LSA loads during system initialization. By adding a rogue DLL name to this list, an attacker achieves persistence with execution in the context of the LSASS process — a highly privileged, long-running system process. This is the primary Lsa registry key targeted by this technique; a companion key (OSConfig) is tested in T1547.005-2.

## What This Dataset Contains

The test modifies the `Security Packages` multi-string value under `HKLM\System\CurrentControlSet\Control\Lsa` to include `AtomicTest.dll`. Two Sysmon EID 13 (RegistryEvent - Value Set) events capture both the write of the new value and the ART-created backup:

```
Registry value set:
  TargetObject: HKLM\System\CurrentControlSet\Control\Lsa\Security Packages old
  Details: ""   (backup of original, written as empty string)

Registry value set:
  TargetObject: HKLM\System\CurrentControlSet\Control\Lsa\Security Packages
  Details: Binary Data
  Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
  User: NT AUTHORITY\SYSTEM
```

Note that the Sysmon rule does not tag these events with `T1547.005` — the rule name field shows `-` (no match). The technique is still evident from the target key path.

The PowerShell EID 4104 script block captures the full operation:

```powershell
$oldvalue = $(Get-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa
  -Name 'Security Packages' | Select-Object -ExpandProperty 'Security Packages');
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa"
  -Name 'Security Packages old' -Value "$oldvalue";
$newvalue = "AtomicTest.dll";
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name 'Security Packages' -Value $newvalue
```

Sysmon EID 1 records `whoami.exe` (tagged T1033) and the PowerShell process that performed the writes (tagged T1083 — the sysmon-modular ruleset matches this PowerShell invocation pattern as File and Directory Discovery). Security EID 4688 records the full process creation chain.

The PowerShell log is overwhelmingly boilerplate: the ~28 test framework formatter script blocks (`{ Set-StrictMode -Version 1; $_.PSMessageDetails }` etc.) surround just 2 substantive script block entries.

## What This Dataset Does Not Contain

**LSASS DLL loading** is not present. The `AtomicTest.dll` named in the registry value does not exist on disk, and in any case the DLL would only be loaded by LSASS at the next system boot — not during this test window.

**Windows Defender did not block this test** — the registry modification succeeded. However, had the DLL actually been present and loaded at boot, Defender behavior monitoring would likely have flagged it.

**No Sysmon EID 7 (ImageLoad) for AtomicTest.dll** is present for the same reason: no DLL load occurs during the capture window.

**Object access auditing is disabled**, so no Security EID 4657 (registry value modification) events are present.

**Sysmon ProcessCreate filtering** means the child PowerShell process writing the registry value is captured via Security EID 4688 but not Sysmon EID 1 (the Sysmon rule tags it T1083, not T1547.005).

## Assessment

The test ran to completion. The registry modification is confirmed by two Sysmon EID 13 events. The complete script block is captured in PowerShell EID 4104. The dataset accurately represents the persistence registration phase of this technique — the moment an adversary inserts their SSP into the LSA package list — without the subsequent DLL loading that would only occur at boot.

## Detection Opportunities Present in This Data

- **Sysmon EID 13**: Any write to `HKLM\System\CurrentControlSet\Control\Lsa\Security Packages` by a user-mode process (as opposed to a system installer) is highly suspicious. The key path alone is sufficient for a high-confidence rule.
- **Sysmon EID 13**: A `Security Packages old` backup value being written immediately before a `Security Packages` modification is an ART-specific artifact and a useful correlation indicator.
- **PowerShell EID 4104**: The script block shows the full target path and the DLL name being inserted. Alerting on `Set-ItemProperty` targeting `Control\Lsa` with `Security Packages` is effective and low-noise.
- **Security EID 4688**: The child PowerShell command line contains the full registry path, offering detection from a second source without Sysmon.
- Temporal correlation of a `whoami.exe` execution immediately before the Lsa registry modification provides behavioral context.
