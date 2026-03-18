# T1548.002-22: Bypass User Account Control — Disable UAC Admin Consent Prompt via ConsentPromptBehaviorAdmin Registry Key

## Technique Context

T1548.002 (Bypass User Account Control) includes not only clever auto-elevate exploits but also direct UAC policy modification. The `ConsentPromptBehaviorAdmin` registry value at `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` controls what happens when an administrator attempts a privileged action: value `2` (the default) requires explicit consent on the secure desktop; value `0` suppresses all prompts entirely, allowing any process running under an admin account to silently gain elevated privileges. Setting this to `0` disables UAC elevation prompts system-wide. Unlike exploit-based bypasses, this is a persistent, system-wide configuration change that survives reboots.

## What This Dataset Contains

The dataset captures approximately 6 seconds of activity on ACME-WS02 (Windows 11 Enterprise, domain member of acme.local).

**PowerShell script block logging (4104)** records the complete attack payload:

```
{$orgValue =(Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin).ConsentPromptBehaviorAdmin
Set-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin -Value 0 -Type Dword -Force}
```

The script first reads the current value (preserving it for cleanup), then sets it to `0`.

**PowerShell 4103 module logging** records each cmdlet call with full parameter bindings:
- `Get-ItemProperty` on the Policies\System path with `-Name ConsentPromptBehaviorAdmin`
- `Set-ItemProperty` with `-Name ConsentPromptBehaviorAdmin`, `-Value 0`, `-Type DWord`, `-Force`

**Sysmon Event 13** (registry value set) captures the modification with a Sysmon rule match:
- `RuleName: technique_id=T1548.002,technique_name=Bypass User Access Control`
- `TargetObject: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin`
- `Details: DWORD (0x00000000)`
- `Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

This is one of the clearest examples in the T1548.002 dataset series where Sysmon's rule engine directly annotates the event with the MITRE technique ID.

**Sysmon Event 1**: `whoami.exe` (ART pre-check) and `powershell.exe` for the attack.

**Sysmon Events 7, 10, 11, 17**: DLL loads, process access to `whoami.exe`, profile file creation, named pipe — ART test framework artifacts.

**Security 4688**: Process creation for `whoami.exe` and `powershell.exe`.

**PowerShell 4103**: `Set-ExecutionPolicy -Bypass -Scope Process -Force` (two ART test framework instances).

## What This Dataset Does Not Contain (and Why)

**No confirmation of bypass success via elevated process**: The test only modifies the registry value; it does not then attempt to use the disabled UAC prompt to run a new elevated process. Success of the configuration change is confirmed by the registry write itself.

**No Sysmon Event 12 (registry key creation)**: The key already exists; only the value is modified, which produces Event 13 (value set), not Event 12.

**No Security object access events**: Object access auditing is disabled in the audit policy, so no registry access audit events appear alongside the Sysmon data.

**No system restart or policy reload telemetry**: The `ConsentPromptBehaviorAdmin` change takes effect immediately for new elevation requests; no reboot is required and no policy change event is logged in the available channels.

## Assessment

The registry modification succeeded — the Sysmon Event 13 with value `0x00000000` confirms it. This technique is distinct from exploit-based bypasses: it requires that the executing process already have administrative privileges (which the SYSTEM context satisfies), and it makes a persistent system-wide change. The Sysmon rule engine correctly identified and tagged this event with the T1548.002 technique annotation, demonstrating that the sysmon-modular configuration has explicit coverage for this key.

## Detection Opportunities Present in This Data

- **Sysmon Event 13**: Registry write to `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` with value `0x00000000` is a high-fidelity, low-noise indicator. The Sysmon rule already annotates this as T1548.002.
- **PowerShell 4104**: Script block explicitly setting `ConsentPromptBehaviorAdmin` to `0` is a direct signature; the full path and value appear verbatim.
- **PowerShell 4103**: `Set-ItemProperty` with `-Name ConsentPromptBehaviorAdmin` and `-Value 0` logged with parameter bindings provides detection without relying on Sysmon.
- **Baseline deviation**: The value `ConsentPromptBehaviorAdmin` should be `2` (or `5`) in a standard enterprise policy. Any change away from the expected value is worth alerting on, particularly when the change is made by `powershell.exe` rather than a Group Policy mechanism.
- **Correlation with privilege escalation**: A `ConsentPromptBehaviorAdmin=0` write followed by subsequent elevation attempts (new processes with admin tokens) in the same session is a strong behavioral chain for a privilege escalation scenario.
