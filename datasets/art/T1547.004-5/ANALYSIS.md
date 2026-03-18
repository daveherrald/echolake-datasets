# T1547.004-5: Winlogon Helper DLL — Winlogon HKLM Userinit Key Persistence - PowerShell

## Technique Context

T1547.004 (Winlogon Helper DLL) covers adversary abuse of the Windows Winlogon process to establish persistence. The `Userinit` registry value under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` controls which programs run when a user logs in. By appending an additional executable to this value (the default is `Userinit.exe`), an attacker ensures their payload runs every time any user logs on to the system. This technique requires write access to HKLM, meaning it is restricted to administrator or SYSTEM-level access. It is associated with multiple threat groups and was used in commodity malware for years before becoming a common red team test.

## What This Dataset Contains

The dataset captures a PowerShell-based implementation of the Userinit persistence modification, executed as NT AUTHORITY\SYSTEM. The central event is a Sysmon Event ID 13 (RegistryEvent - Value Set) with the rule tag `technique_id=T1547.004,technique_name=Winlogon Helper DLL`:

```
Registry value set:
  TargetObject: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit
  Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
  User: NT AUTHORITY\SYSTEM
```

The PowerShell script block (EID 4104) that performed the write was captured in full:

```
& {Set-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\"
  "Userinit" "Userinit.exe, C:\Windows\System32\cmd.exe" -Force}
```

This appends `cmd.exe` alongside the legitimate `Userinit.exe`, so that cmd.exe launches for every interactive logon.

Preceding the write, a Sysmon EID 1 records `whoami.exe` execution tagged `technique_id=T1033` — the ART test framework verifying execution context. A second EID 1 captures the child PowerShell process spawned to run the `Set-ItemProperty` command, tagged `technique_id=T1059.001`. Security EID 4688 confirms the process creation with the full command line visible. Security EID 4703 records privilege token adjustment for the SYSTEM process enabling multiple sensitive privileges (SeLoadDriverPrivilege, SeRestorePrivilege, SeTakeOwnershipPrivilege, among others).

The PowerShell log (EID 4103/4104) is dominated by ART test framework boilerplate: repeated `{ Set-StrictMode -Version 1; $_.PSMessageDetails }` and similar internal formatter blocks. The two substantive 4104 entries are the outer `& {...}` wrapper and the inner script block body.

## What This Dataset Does Not Contain

**Registry cleanup telemetry** is absent from this window. ART restores the original Userinit value as part of cleanup, but those events fall outside the 4-second capture window.

**No DLL loading or process execution at logon** is present, because the payload is only triggered at the next interactive user logon, which does not occur during the test.

**No Sysmon EID 12 (RegistryEvent - Object Create/Delete)** is present, because the key already exists; only the value is modified.

**Object access auditing is disabled** (audit_policy object_access: none), so there are no Security EID 4663 registry access events.

**Sysmon process creation filtering** (include-mode) means most PowerShell child processes are not captured in Sysmon EID 1 — coverage comes from Security EID 4688 for the full process inventory.

## Assessment

The test ran to completion. The registry modification is confirmed by Sysmon EID 13 with the sysmon-modular rule correctly attributing the technique. The full PowerShell script block is captured verbatim in EID 4104. The dataset faithfully represents the attack telemetry for this vector: a privileged PowerShell process silently writing to a logon autostart registry key.

## Detection Opportunities Present in This Data

- **Sysmon EID 13**: Registry write to `HKLM\...\Winlogon\Userinit` by any process other than a trusted Windows installer is high-fidelity. The sysmon-modular ruleset fires and labels it `T1547.004`.
- **PowerShell EID 4104**: The script block containing `Set-ItemProperty` targeting the Winlogon key is fully visible and unobfuscated.
- **Security EID 4688**: The child PowerShell process command line contains the registry path and the appended `cmd.exe` value, providing detection from a second, independent log source.
- **Security EID 4703**: Token privilege adjustment for SYSTEM enabling `SeLoadDriverPrivilege` and `SeRestorePrivilege` in conjunction with a Winlogon registry write provides behavioral correlation.
- Correlation of `whoami.exe` (EID 4688/Sysmon EID 1) immediately preceding a Winlogon registry modification is a reliable behavioral indicator.
