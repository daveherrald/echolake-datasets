# T1548.002-26: Bypass User Account Control — Disable ConsentPromptBehaviorAdmin via registry keys

## Technique Context

T1548.002 (Bypass User Account Control) includes registry-based methods that weaken or
eliminate UAC enforcement. This test sets
`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin`
to `0`, which configures Windows to elevate administrators without prompting when they
run applications requesting elevation. The default value is `5` (prompt for consent on
the secure desktop). Setting this value to `0` silently auto-elevates any process
requesting high integrity when the user is a member of the Administrators group —
effectively neutering UAC for administrative accounts without fully disabling it.

This is a targeted weakening rather than a full UAC shutdown (`EnableLUA = 0`), making
it potentially less obvious to monitoring tools looking only for complete UAC disablement.

## What This Dataset Contains

The dataset spans roughly five seconds of telemetry (00:11:16–00:11:21 UTC).

**Security 4688 — full process chain:**
1. `whoami.exe` — ART pre-check
2. `cmd.exe`:
   ```
   "cmd.exe" /c reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
             /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 0 /f
   ```
3. `reg.exe`:
   ```
   reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
           /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 0 /f
   ```
   All three processes show `TokenElevationTypeDefault (1)`, Mandatory Label `S-1-16-16384`.

**Sysmon Event 13 — registry write confirmed:**
```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin
= DWORD (0x00000000)
```
RuleName: `technique_id=T1548.002,technique_name=Bypass User Access Control` — the
sysmon-modular config explicitly matches this key write as T1548.002.

**Sysmon Event 1 — three process creates:**
- `whoami.exe` (T1033 rule)
- `cmd.exe` (T1059.003 rule)
- `reg.exe` (T1012 rule)

**Security 4703 — token rights adjusted:** SYSTEM-level privilege enablement.

## What This Dataset Does Not Contain (and Why)

- **The behavioral effect of the setting.** Setting `ConsentPromptBehaviorAdmin = 0`
  means subsequent elevations on that system will silently auto-elevate. No downstream
  auto-elevation events appear because no applications requested elevation in this test
  window.
- **ART cleanup write.** The cleanup step restores the original value; this is outside
  the bundled telemetry window.
- **`PromptOnSecureDesktop` key modification.** Some implementations also set this
  companion key; it is not modified in this test.
- **Group Policy conflict detection.** If Group Policy enforces `ConsentPromptBehaviorAdmin`,
  this reg write would be overwritten at the next refresh. No Group Policy reapplication
  events appear.

## Assessment

This dataset demonstrates targeted UAC weakening at the consent-prompt level. The
technique is more surgical than `EnableLUA = 0` and may go unnoticed by monitoring
focused only on full UAC disablement. The Sysmon Event 13 with a T1548.002 rule tag
provides labeled evidence, and the Security 4688 chain gives full command-line
visibility. Structurally this dataset is nearly identical to test 8 and test 25,
differing only in the specific key and value modified; this family similarity makes
cluster-based detection across all three variants practical.

## Detection Opportunities Present in This Data

- **Sysmon Event 13:** Write to `HKLM\...\Policies\System\ConsentPromptBehaviorAdmin`
  with value `0` — directly tagged as T1548.002.
- **Security 4688:** `reg.exe` argument setting `ConsentPromptBehaviorAdmin /d 0` —
  value `0` is the attack-relevant change; values other than `5` (default) or `2`
  (prompt for credentials) warrant investigation.
- **Sysmon Event 1:** `reg.exe` child of `cmd.exe` child of `powershell.exe` with
  `Policies\System` key path containing `ConsentPromptBehaviorAdmin`.
- **Correlation with tests 8 and 25:** `ConsentPromptBehaviorAdmin = 0` together with
  `EnableLUA = 0` and/or `UACDisableNotify = 1` indicates a systematic attempt to
  dismantle UAC across all enforcement layers.
- **Baseline deviation:** The default value is `5`; any `reg.exe` write setting this to
  `0` or `1` is anomalous in an enterprise environment with enforced UAC policy.
