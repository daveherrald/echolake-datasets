# T1548.002-25: Bypass User Account Control — Disable UAC notification via registry keys

## Technique Context

T1548.002 (Bypass User Account Control) includes registry-based approaches that suppress
or disable UAC without exploiting an auto-elevating binary. This test writes
`HKLM\SOFTWARE\Microsoft\Security Center\UACDisableNotify = 1`, which instructs the
Windows Security Center to suppress UAC notifications. Unlike `EnableLUA = 0` (test 8),
this key does not fully disable UAC enforcement — it suppresses the Security Center
warning that would otherwise alert a user that UAC has been modified. Attackers use this
as a companion action to other UAC-disabling changes to prevent the Security Center icon
from indicating a security problem.

The technique requires write access to HKLM, which this test has through the SYSTEM
execution context.

## What This Dataset Contains

The dataset spans roughly five seconds of telemetry (00:10:57–00:11:02 UTC).

**Security 4688 — full process chain:**
1. `whoami.exe` — ART pre-check, parent `powershell.exe`
2. `cmd.exe`:
   ```
   "cmd.exe" /c reg add "HKLM\SOFTWARE\Microsoft\Security Center" /v UACDisableNotify /t REG_DWORD /d 1 /f
   ```
3. `reg.exe`:
   ```
   reg add "HKLM\SOFTWARE\Microsoft\Security Center" /v UACDisableNotify /t REG_DWORD /d 1 /f
   ```
   All processes show `TokenElevationTypeDefault (1)` and Mandatory Label `S-1-16-16384`.

**Sysmon Event 13 — registry write confirmed:**
```
HKLM\SOFTWARE\Microsoft\Security Center\UACDisableNotify = DWORD (0x00000001)
```
RuleName: `technique_id=T1548.002,technique_name=Bypass User Access Control` — this
key is explicitly covered by the sysmon-modular T1548.002 detection ruleset.

**Sysmon Event 1 — three process creates:**
- `whoami.exe` (T1033 rule)
- `cmd.exe` (T1059.003 rule)
- `reg.exe` (T1012 rule)

**Security 4703 — token rights adjusted:** SYSTEM-level privilege enablement on
`powershell.exe`.

## What This Dataset Does Not Contain (and Why)

- **Security Center UI suppression behavior.** The dataset captures the registry write
  itself; the resulting behavior (suppressed Security Center balloon) is not observable
  in event logs.
- **ART cleanup (restoration of the key).** The key is restored by the cleanup step
  after the test window.
- **Sysmon Event 13 for the cleanup write.** The cleanup write is outside the bundled
  telemetry window.
- **Additional UAC policy keys.** This test modifies only `UACDisableNotify`; it does
  not touch `EnableLUA` or `ConsentPromptBehaviorAdmin`. Correlation with tests 8 and 26
  would be needed to see a full UAC-disablement sequence.

## Assessment

This dataset shows a UAC notification suppression step rather than a full UAC bypass.
In practice, attackers use this key alongside `EnableLUA = 0` or
`ConsentPromptBehaviorAdmin = 0` to prevent the Security Center from drawing attention
to the modified UAC state. The Sysmon Event 13 with an explicit T1548.002 rule tag
and the complete Security 4688 process chain provide direct, actionable detection
evidence. The Security Center registry path (`HKLM\...\Security Center`) is distinct
from the UAC policy path (`HKLM\...\Policies\System`) used in tests 8 and 26.

## Detection Opportunities Present in This Data

- **Sysmon Event 13:** Write to `HKLM\SOFTWARE\Microsoft\Security Center\UACDisableNotify`
  with value `1` — directly tagged as T1548.002 by sysmon-modular.
- **Security 4688:** `reg.exe` command line setting `UACDisableNotify /d 1` under the
  Security Center key.
- **Sysmon Event 1:** `reg.exe` spawned by `cmd.exe` spawned by `powershell.exe` with
  Security Center key path in the argument list.
- **Correlation opportunity:** `UACDisableNotify = 1` combined with `EnableLUA = 0`
  or `ConsentPromptBehaviorAdmin = 0` in the same session indicates a deliberate attempt
  to both disable UAC and suppress the alert.
- **Process chain:** `powershell.exe` → `cmd.exe /c reg add HKLM\...\Security Center`
  is unusual; Security Center keys are not modified by normal administrative workflows.
