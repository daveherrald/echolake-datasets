# T1547.004-4: Winlogon Helper DLL — Winlogon HKLM Shell Key Persistence (PowerShell)

## Technique Context

T1547.004 (Winlogon Helper DLL) abuses Winlogon's startup process by modifying the `Shell` value in the Windows logon registry keys. This test targets the **HKLM** path (`HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell`), the machine-wide variant that affects every user who logs on to the system. Unlike the HKCU variant (T1547.004-1), modifying the HKLM path requires administrator or SYSTEM privileges. The payload appended is `C:\Windows\System32\cmd.exe`, added after `explorer.exe`. When any user logs on, both `explorer.exe` and `cmd.exe` will launch as part of the shell initialization.

This dataset captures the **undefended** execution on ACME-WS06 with Defender disabled. The defended variant (ACME-WS02) produced 39 sysmon, 11 security, 38 powershell, 1 application, and 1 taskscheduler event. The undefended dataset shows 39 sysmon, 4 security, 101 powershell, and 1 system event — the security count difference reflects the defended host's additional process creation events from Defender process interrogation; the additional taskscheduler and application events in the defended variant are background activity differences between the two hosts.

The critical difference between T1547.004-1 (HKCU) and T1547.004-4 (HKLM) from a detection perspective is that this HKLM variant **does** generate a Sysmon EID 13 event, while the HKCU variant does not. The sysmon-modular configuration has an explicit named rule for the HKLM Winlogon Shell path.

## What This Dataset Contains

The dataset spans approximately 5 seconds on ACME-WS06 and contains 145 events across four log sources.

**PowerShell EID 4104 and 4103** document the test payload:

```powershell
Set-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" "Shell" "explorer.exe, C:\Windows\System32\cmd.exe" -Force
```

The EID 4103 module logging event records `CommandInvocation(Set-ItemProperty)` with path, name (`Shell`), and value (`explorer.exe, C:\Windows\System32\cmd.exe`). The cleanup script (`Remove-ItemProperty` on the HKLM Shell value) is also captured in 4104.

**Sysmon (39 events, EIDs 1, 7, 10, 11, 13, 17):**

- **EID 13 (RegistrySetValue):** Two EID 13 events are present. The first captures the attack:
  ```
  RuleName: technique_id=T1547.004,technique_name=Winlogon Helper DLL
  TargetObject: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell
  Details: explorer.exe, C:\Windows\System32\cmd.exe
  Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
  User: NT AUTHORITY\SYSTEM
  ```
  This is the only technique in the T1547.004 batch where the registry modification is directly captured by Sysmon with an explicit T1547.004 rule tag. The value content (`explorer.exe, C:\Windows\System32\cmd.exe`) is fully visible in the `Details` field.

  The second EID 13 is a background write from `svchost.exe` to a Windows Software Protection Platform scheduled task registry path — an unrelated background maintenance event that happened to occur during the test window.

- **EID 1 (ProcessCreate):** Four process creates: `whoami.exe` (T1033), the attack `powershell.exe` (T1059.001) with the `Set-ItemProperty` HKLM command, a cleanup `powershell.exe`, and a second `whoami.exe`.

- **EID 10 (ProcessAccess):** Four events tagged `T1055.001` — test framework handle acquisition.

- **EID 17 (PipeCreate):** Three named pipe creation events.

- **EID 11 (FileCreate):** One file create for a PowerShell profile data artifact.

- **EID 7 (ImageLoad):** 25 DLL load events for PowerShell instances.

**Security (4 events, all EID 4688):** Process creation records for `whoami.exe` and both `powershell.exe` instances with full command lines. The attack PowerShell's 4688 record independently captures the HKLM Winlogon Shell modification:

```
CommandLine: "powershell.exe" & {Set-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" "Shell" "explorer.exe, C:\Windows\System32\cmd.exe" -Force}
```

**System (1 event, EID 35):** W32Time time source change to `ACME-DC01.acme.local` — ambient NTP activity, unrelated to the test.

## What This Dataset Does Not Contain

**No logon-triggered execution.** No logon occurred during the test window; `cmd.exe` did not launch from the modified Winlogon shell. The persistence was installed but not triggered.

**No Defender telemetry.** The HKLM Winlogon Shell modification is not blocked by Defender. The defended and undefended datasets are structurally equivalent from a technique coverage perspective.

**No second Sysmon EID 13 for the cleanup.** The cleanup `Remove-ItemProperty` removes the value; if Sysmon monitors removes as well as sets, a second EID 13 or an EID 12 (RegistryKeyDelete) might appear. In this dataset the sample does not include a cleanup-phase registry event.

## Assessment

The contrast between T1547.004-1 (HKCU) and T1547.004-4 (HKLM) reveals an important asymmetry in sysmon-modular's coverage: the machine-wide HKLM Winlogon Shell path has an explicit named detection rule; the per-user HKCU path does not. This means an adversary operating without elevation who uses HKCU gets less observable telemetry — a counterintuitive situation where the lower-privilege technique is less detectable through Sysmon.

For T1547.004-4, the Sysmon EID 13 with the T1547.004 rule tag provides a clean, actionable alert anchor. The `Details` field shows the exact modified value including the appended `cmd.exe`, making the malicious addition immediately visible without further context.

## Detection Opportunities Present in This Data

- **Sysmon EID 13 (tagged T1547.004):** The sysmon-modular ruleset explicitly names this technique for `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell`. Any modification to this value that appends an executable after `explorer.exe` warrants investigation.

- **Sysmon EID 13, value content:** The `Details` field shows `explorer.exe, C:\Windows\System32\cmd.exe`. Any Shell value containing more than `explorer.exe` (the legitimate default) is suspicious. Deviations from the expected value `explorer.exe` are detectable by content inspection.

- **PowerShell EID 4104:** Script blocks with `Set-ItemProperty` targeting `HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\` and setting `Shell` to a value containing a second executable. The HKLM path combined with an appended executable name is highly specific.

- **PowerShell EID 4103:** Structured record of `Set-ItemProperty` with path, name (`Shell`), and value parameters. Lower fidelity than 4104 but provides parseable fields.

- **Security EID 4688:** `powershell.exe` command lines referencing `Winlogon`, `Shell`, and `Set-ItemProperty`. Correlate with EID 13 to confirm the write occurred.

- **Baseline comparison:** Monitoring the HKLM Winlogon Shell value for deviations from the known-good value (`explorer.exe`) is a low-noise, high-value detection approach for this technique — any deviation indicates either legitimate customization (rare) or persistence.
