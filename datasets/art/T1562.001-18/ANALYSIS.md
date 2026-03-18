# T1562.001-18: Disable or Modify Tools — Tamper with Windows Defender Registry

## Technique Context

MITRE ATT&CK T1562.001 (Impair Defenses: Disable or Modify Tools) covers adversary actions
to disable or degrade security tooling. One of the most direct methods on Windows is writing
to the Windows Defender policy registry key to set `DisableAntiSpyware = 1`. This single
registry value, when written under `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`,
signals to the Defender service that anti-spyware scanning should be disabled via Group Policy.
Ransomware operators and post-exploitation frameworks routinely perform this action before
deploying payloads or running credential access tools.

## What This Dataset Contains

The dataset captures 37 Sysmon events, 10 Security events, and 38 PowerShell events spanning
approximately 5 seconds on ACME-WS02 (Windows 11 Enterprise, domain member of acme.local).

The central event is a Sysmon Event ID 13 (Registry value set) with RuleName
`technique_id=T1562.001,technique_name=Disable or Modify Tools`:

```
TargetObject: HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware
Details: DWORD (0x00000001)
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: NT AUTHORITY\SYSTEM
```

The process chain is visible across both Sysmon and Security logs. A parent PowerShell
process (PID 5868) spawns a child PowerShell (PID 1968) via the ART test framework. Security
4688 captures the child's full command line:

```
"powershell.exe" & {Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
  -Name DisableAntiSpyware -Value 1}
```

PowerShell Script Block Logging (4104) records the same payload in two forms: wrapped with
the ART `& { }` invocation pattern and unwrapped. Module logging (4103) records
`Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass` — the standard ART
test framework preamble appearing twice, once per PowerShell instance. A `whoami.exe` process
create (Sysmon EID 1, Security 4688) precedes the attack, which is the ART pre-execution
identity check. All processes exit cleanly (0x0).

## What This Dataset Does Not Contain (and Why)

**No Defender service state changes.** Writing the registry key alone does not immediately
stop the Defender service; a service restart or group policy refresh is required. No service
control events, System log entries, or Defender operational events are present.

**No registry audit events (Security 4657).** The audit policy has object access auditing
disabled (`object_access: none`), so registry writes do not appear in the Security log.
The visibility here comes entirely from Sysmon EID 13, which monitors registry writes
independently of audit policy.

**No persistence or follow-on activity.** This test executes the single tamper action in
isolation. Real adversaries would follow this with payload execution or further defense
suppression.

**Sysmon ProcessCreate is filtered.** The sysmon-modular include-mode configuration captures
`powershell.exe` because it matches the T1059.001 include rule. The child `whoami.exe` is
captured via the T1033 rule. Not all process creations on the system appear here.

## Assessment

The test succeeded. The registry write completes and exits with status 0x0. The key detection
artifact — Sysmon EID 13 with the exact registry path and DWORD value — is present. Windows
Defender was fully active during execution; the registry write bypasses Defender's self-
protection because it operates under NT AUTHORITY\SYSTEM and writes to the policy path,
which Defender treats as a legitimate Group Policy override.

## Detection Opportunities Present in This Data

- **Sysmon EID 13**: Registry write to `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware`
  with value 1. The sysmon-modular ruleset already tags this with technique_id=T1562.001.
  A rule on this exact path and value produces near-zero false positives in most environments.

- **Security 4688 + PowerShell 4104 correlation**: The child PowerShell command line contains
  `Set-ItemProperty` combined with `DisableAntiSpyware`, visible in both the process creation
  event and the script block log. Alerting on `DisableAntiSpyware` in PowerShell command
  lines or script blocks is a high-fidelity signal.

- **Test framework artifact**: The `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass`
  pattern in 4103 module logging is a recognizable ART artifact but is also used by many
  legitimate automation tools; treat it as context rather than a primary indicator.
