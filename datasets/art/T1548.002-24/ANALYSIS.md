# T1548.002-24: Bypass User Account Control — Disable UAC - Switch to Secure Desktop When Prompting for Elevation via Registry Key

## Technique Context

T1548.002 (Bypass User Account Control) includes direct UAC policy modifications alongside exploit-based bypasses. The `PromptOnSecureDesktop` registry value at `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` controls whether UAC prompts appear on the isolated secure desktop (value `1`, the default) or on the standard interactive desktop (value `0`). When set to `0`, elevation prompts appear on the user's regular desktop rather than the secure desktop. This is significant because the secure desktop isolates the UAC prompt from all non-system processes, preventing UI injection attacks against the prompt. Disabling secure desktop mode makes UAC prompts susceptible to programmatic click-through attacks, significantly weakening the UAC boundary without fully disabling it.

## What This Dataset Contains

The dataset captures approximately 5 seconds of activity on ACME-WS02 (Windows 11 Enterprise, domain member of acme.local).

**PowerShell script block logging (4104)** records the attack payload:

```
{Set-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name PromptOnSecureDesktop -Value 0 -Type Dword -Force}
```

This is a single-line registry modification — notably simpler than test 22, with no value preservation or cleanup.

**PowerShell 4103 module logging** records `Set-ItemProperty` with full parameter bindings:
- `-Name PromptOnSecureDesktop`
- `-Value 0`
- `-Type DWord`
- `-Force`
- `-Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`

**Sysmon Event 13** captures the registry write with MITRE annotation:
- `RuleName: technique_id=T1548.002,technique_name=Bypass User Access Control`
- `TargetObject: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`
- `Details: DWORD (0x00000000)`
- `Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- `User: NT AUTHORITY\SYSTEM`

**Sysmon Event 1**: `whoami.exe` (ART pre-check) and `powershell.exe` for the attack payload.

**Sysmon Events 7, 11, 17**: DLL loads, PowerShell startup profile creation, named pipe — ART test framework artifacts.

**Security 4688**: Process creation for `whoami.exe` and `powershell.exe`.

**Security 4703**: Token right adjustment on the SYSTEM logon session.

**PowerShell 4103**: `Set-ExecutionPolicy -Bypass -Scope Process -Force` (two ART test framework instances).

## What This Dataset Does Not Contain (and Why)

**No Sysmon Event 10 (process access)**: Unlike most other tests in this series, no `powershell.exe` → `whoami.exe` process access event appears here. This is likely due to timing — the `whoami.exe` process was very short-lived and the access event may have been missed or the Sysmon rule did not fire for this particular execution instance.

**No evidence of subsequent UI injection or prompt click-through**: The test only performs the configuration change; no follow-on attack using the weakened UAC prompt was executed.

**No Security object access events**: Object access auditing is disabled.

**No value preservation or rollback visible in the data**: Unlike test 22, the ART test for this technique does not read the original value first; the original `PromptOnSecureDesktop` state is unknown from the data alone.

## Assessment

The registry modification succeeded: `PromptOnSecureDesktop` was set to `0`, disabling secure desktop isolation for UAC prompts. This is a subtler UAC weakening than test 22 (`ConsentPromptBehaviorAdmin=0`) — it does not remove prompts entirely, but makes them vulnerable to automated interaction. The Sysmon rule set correctly identifies and annotates this key as T1548.002. This technique is often used in combination with other bypass methods to create a more permissive UAC environment before attempting a follow-on attack.

## Detection Opportunities Present in This Data

- **Sysmon Event 13**: Write to `HKLM\...\Policies\System\PromptOnSecureDesktop` with value `0x00000000` is a direct, annotated indicator. The Sysmon rule explicitly covers this key.
- **PowerShell 4104**: Script block setting `PromptOnSecureDesktop` to `0` via `Set-ItemProperty` on the Policies\System path is a precise signature.
- **PowerShell 4103**: Parameter bindings logging `-Name PromptOnSecureDesktop` with `-Value 0` provide detection without Sysmon.
- **Baseline deviation**: `PromptOnSecureDesktop` should be `1` in any standard enterprise environment. Any modification to `0` by a non-Group Policy mechanism (i.e., not `svchost.exe` processing a GPO) is suspicious.
- **Companion technique detection**: `PromptOnSecureDesktop=0` and `ConsentPromptBehaviorAdmin=0` (test 22) on the same host within a short time window suggests a systematic UAC weakening campaign and should trigger elevated alert priority.
- **Registry key pairing**: Monitoring both `ConsentPromptBehaviorAdmin` and `PromptOnSecureDesktop` under `Policies\System` as a pair covers the full spectrum of UAC policy weakening, since adversaries may set one or both depending on their specific objective.
