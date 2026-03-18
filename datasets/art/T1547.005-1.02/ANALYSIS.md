# T1547.005-1: Security Support Provider — Modify HKLM Lsa Security Packages

## Technique Context

T1547.005 (Security Support Provider) abuses the Windows Security Support Provider (SSP) and Authentication Package architecture to load adversary-controlled DLLs into LSASS at system boot. The `Security Packages` multi-string value at `HKLM\System\CurrentControlSet\Control\Lsa` lists SSP/AP DLLs that the Local Security Authority loads during initialization. By adding a rogue DLL name to this list, an attacker achieves persistent execution inside `lsass.exe` — one of the most privileged and long-running processes on Windows — on every system startup. This requires administrator or SYSTEM privileges to modify the Lsa registry key.

This dataset captures the **undefended** execution of ART test T1547.005-1 on ACME-WS06 with Defender disabled. The defended variant (ACME-WS02) showed 35 sysmon, 10 security, and 40 powershell events — slightly less than the undefended 49 sysmon, 12 security, and 107 powershell. Defender does not block the `Security Packages` registry modification in the defended test; the event count differences reflect host variability rather than Defender intervention.

## What This Dataset Contains

The dataset spans approximately 6 seconds on ACME-WS06 and contains 169 events across five log sources (sysmon, security, powershell, system, wmi).

**PowerShell EID 4104** captures the full attack script:

```powershell
$oldvalue = $(Get-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa -Name 'Security Packages' | Select-Object -ExpandProperty 'Security Packages');
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name 'Security Packages old' -Value "$oldvalue";
$newvalue = "AtomicTest.dll";
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name 'Security Packages' -Value $newvalue
```

The test reads the existing `Security Packages` value, backs it up as `Security Packages old`, then replaces the value with `AtomicTest.dll`. The ART cleanup script restores the original value from the backup.

**Sysmon (49 events, EIDs 1, 7, 10, 11, 13, 17):**

The dataset contains 2 EID 13 (RegistrySetValue) events. Based on the script content, these capture: (1) the backup write (`Security Packages old` value) and (2) the modified `Security Packages` value. The EID 13 events are present in the full 49-event dataset but were not included in the 20-event representative sample. Both writes target `HKLM\System\CurrentControlSet\Control\Lsa` and are performed by `powershell.exe` running as `NT AUTHORITY\SYSTEM`. The rule name for these events is `-` (no named rule match) — sysmon-modular does not have a specific T1547.005 rule for the `Security Packages` path, in contrast to the `Authentication Packages` path which does have a named T1547.002 rule.

- **EID 1 (ProcessCreate):** Four process creates: `whoami.exe` (T1033), the attack `powershell.exe` (T1083) with the full Security Packages modification script, and a cleanup `powershell.exe`.

- **EID 11 (FileCreate):** Three events, including `C:\Windows\System32\LogFiles\WMI\RtBackup\EtwRTAdmin_PS_Provider.etl` (a WMI ETL trace file artifact from PowerShell's administrative provider initialization) and PowerShell profile data files.

- **EID 10 (ProcessAccess):** Four events tagged `T1055.001` — test framework handle acquisition.

- **EID 17 (PipeCreate):** Three named pipe creation events.

- **EID 7 (ImageLoad):** 33 DLL load events across multiple PowerShell instances — the highest EID 7 count in the T1547.005 batch, reflecting the three distinct PowerShell process initializations in this test.

**Security (12 events, EIDs 4688 × 6, 4624 × 2, 4672 × 2, 4799 × 2):**

- **EID 4688:** Six process creates including `powershell.exe` instances with the `Security Packages` modification script and cleanup script, `svchost.exe` launching BITS (`C:\Windows\System32\svchost.exe -k netsvcs -p -s BITS`), and `WmiApSrv.exe`.

- **EID 4624 (Logon):** Two SYSTEM logon events (logon type 5, service logon) — background Windows service activity coinciding with the test window.

- **EID 4672 (Special Privileges):** Two privileged logon events for the SYSTEM account.

- **EID 4799 (Security-Enabled Local Group Membership Enumerated):** Two events showing enumeration of `Administrators` and `Backup Operators` groups by `ACME-WS06$` (the machine account) — a normal background activity triggered by service startups during the test window.

**System (1 event, EID 7040):** Background Intelligent Transfer Service changed from auto start to demand start — ambient OS activity.

**WMI (1 event, EID 5860):** A WMI query registration: `SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = 'wsmprovhost.exe'` — a WinRM/PowerShell remote management subscription created by the SYSTEM account. This is a test framework artifact from the SimAgent PowerShell execution environment.

## What This Dataset Does Not Contain

**No LSASS DLL loading.** `AtomicTest.dll` is named in the registry but the DLL does not exist at a valid path on this host. Even if the file existed, LSASS would only load it at the next system boot. No Sysmon EID 7 showing `AtomicTest.dll` loading into `lsass.exe` is present.

**No named T1547.005 Sysmon rule.** Unlike T1547.002 (Authentication Packages), the `Security Packages` path does not have an explicit sysmon-modular rule. The EID 13 events fire on the default catch-all rule, meaning they lack technique tagging.

**No Security EID 4657 (Registry Object Access).** SACL-based registry write auditing is not enabled.

## Assessment

The primary evidence for this technique is the combination of PowerShell EID 4104 (script content showing `Set-ItemProperty` on the `Security Packages` LSA key) and the two Sysmon EID 13 events (registry writes to `HKLM\System\CurrentControlSet\Control\Lsa`). Together these tell the complete story of the modification.

The absence of a named sysmon-modular rule for `Security Packages` (while `Authentication Packages` has one) is a coverage gap worth noting. Both paths are equally sensitive LSA keys that, when modified, can load arbitrary code into LSASS.

The background Security events (4624, 4672, 4799) and System/WMI events are ambient activity that happened to fall within the test window — they are not related to the T1547.005 technique and would be present in any 6-second window on a domain-joined host with active services.

## Detection Opportunities Present in This Data

- **Sysmon EID 13:** Registry writes to `HKLM\System\CurrentControlSet\Control\Lsa\Security Packages` by any process other than the Windows installer or legitimate system configuration utilities. The `Details` field shows the new multi-string value content — any entry other than the expected Windows defaults (`kerberos`, `msv1_0`, `schannel`, `wdigest`, etc.) warrants investigation.

- **PowerShell EID 4104:** Script blocks containing `Set-ItemProperty` targeting `HKLM:\System\CurrentControlSet\Control\Lsa` with `Security Packages` as the `Name` parameter. The presence of a non-system DLL name in the value is the indicator.

- **PowerShell EID 4103:** `CommandInvocation(Set-ItemProperty)` with path `HKLM:\System\CurrentControlSet\Control\Lsa` and `Name=Security Packages`. Structured module logging captures the operation even without full script block content.

- **Security EID 4688:** `powershell.exe` command lines referencing `HKLM:\System\CurrentControlSet\Control\Lsa` and `Security Packages` in combination.

- **Value baseline monitoring:** The `Security Packages` value has a known, stable set of default entries on any given Windows version. Out-of-band monitoring comparing the current value against a known baseline can detect additions that Sysmon or Security logs might not surface until the next write event.
