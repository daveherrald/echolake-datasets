# T1562.001-19: Disable or Modify Tools — Disable Microsoft Office Security Features

## Technique Context

MITRE ATT&CK T1562.001 (Impair Defenses: Disable or Modify Tools) encompasses disabling
application-layer security controls, not just endpoint protection software. Microsoft Office
provides multiple security layers that prevent malicious macro execution and open untrusted
documents in Protected View. Adversaries disable these controls through registry manipulation
before delivering Office-based payloads — a critical preparatory step in phishing campaigns
that rely on macros or embedded objects. Disabling VBA macro warnings and all three Protected
View modes simultaneously leaves the target fully exposed to document-based attacks.

## What This Dataset Contains

The dataset captures 50 Sysmon events, 10 Security events, and 64 PowerShell events spanning
approximately 6 seconds on ACME-WS02 (Windows 11 Enterprise, domain member of acme.local).

Four Sysmon EID 13 (Registry value set) events are the primary attack artifacts, all tagged
with `RuleName: T1562,office`:

```
HKU\.DEFAULT\Software\Microsoft\Office\16.0\Excel\Security\VBAWarnings
  → DWORD (0x00000001)

HKU\.DEFAULT\Software\Microsoft\Office\16.0\Excel\Security\ProtectedView\DisableInternetFilesInPV
  → DWORD (0x00000001)

HKU\.DEFAULT\Software\Microsoft\Office\16.0\Excel\Security\ProtectedView\DisableUnsafeLocationsInPV
  → DWORD (0x00000001)

HKU\.DEFAULT\Software\Microsoft\Office\16.0\Excel\Security\ProtectedView\DisableAttachementsInPV
  → DWORD (0x00000001)
```

All four writes are attributed to `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
running as `NT AUTHORITY\SYSTEM` (PID 2256). The Security 4688 event captures the full
child PowerShell command line, and PowerShell 4104 script block logging records the payload:

```powershell
New-Item -Path "HKCU:\Software\Microsoft\Office\16.0\Excel"
New-Item -Path "HKCU:\Software\Microsoft\Office\16.0\Excel\Security"
New-Item -Path "HKCU:\Software\Microsoft\Office\16.0\Excel\Security\ProtectedView"
New-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Excel\Security" -Name "VBAWarnings" -Value "1" -PropertyType "Dword"
New-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Excel\Security\ProtectedView" -Name "DisableInternetFilesInPV" -Value "1" -PropertyType "Dword"
...
```

Note that the script targets `HKCU:` while Sysmon records writes under `HKU\.DEFAULT\` —
this is because execution runs as SYSTEM, mapping HKCU to the default user hive. The standard
ART test framework preamble (`Set-ExecutionPolicy Bypass`, `whoami.exe` check) is present.
All processes exit cleanly (0x0).

## What This Dataset Does Not Contain (and Why)

**No Office application events.** The Office Trust Center writes to these keys but does not
produce application log entries for registry changes. No Office diagnostic or audit events
are present because Office was not running during the test.

**No Security 4657 registry audit events.** Object access auditing is disabled in the
audit policy, so registry writes are not captured in the Security log — only Sysmon EID 13
provides registry visibility.

**User hive targeting limitation.** The test writes to `HKU\.DEFAULT\` (SYSTEM's HKCU),
not to the actual logged-in user's hive. A real adversary running under a domain user account
would write to that user's hive directly. This test demonstrates the registry path and values
but not necessarily the targeting a human attacker would use.

**No follow-on document delivery.** This dataset is an isolated test of the configuration
phase. The actual phishing document or payload delivery that would follow is not present.

## Assessment

The test succeeded. All four registry values were written and all processes exited with
status 0x0. The sysmon-modular ruleset correctly identifies and tags these writes as Office
security feature tampering. Windows Defender did not block the registry writes, as policy-
path modifications targeting application settings are not in Defender's self-protection scope.

## Detection Opportunities Present in This Data

- **Sysmon EID 13 on Office security registry paths**: Any write to keys matching
  `\Software\Microsoft\Office\*\Security\VBAWarnings` or `DisableInternetFilesInPV` /
  `DisableUnsafeLocationsInPV` / `DisableAttachementsInPV` is high-fidelity. The sysmon-
  modular ruleset already matches these with the `T1562,office` rule name.

- **PowerShell 4104 script block content**: The presence of `VBAWarnings` or `DisableInternetFilesInPV`
  in script block text is a reliable indicator. Combined with `New-ItemProperty` or
  `Set-ItemProperty`, this pattern rarely appears in legitimate automation.

- **Security 4688 command line**: The child PowerShell process command line visible in the
  4688 event contains the full registry paths, enabling detection at the process creation
  layer even without Sysmon.

- **Cluster detection**: All four writes occur within 15ms of each other from the same PID.
  A rule looking for multiple Office security registry writes in a short window provides
  contextual richness beyond single-key alerting.
