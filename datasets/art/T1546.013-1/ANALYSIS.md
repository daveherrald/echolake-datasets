# T1546.013-1: PowerShell Profile — Append Malicious Start-Process Cmdlet

## Technique Context

T1546.013 (PowerShell Profile) establishes persistence by modifying a PowerShell profile script so that arbitrary code executes each time a new PowerShell session is started. On Windows, profile locations include the per-user `$PROFILE` path (`Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1`) and the all-users equivalent. Because PowerShell profiles are executed before any user-provided script, they are an attractive persistence mechanism — the payload runs automatically in the context of whoever launches PowerShell, which can include SYSTEM if any service or task spawns a PowerShell session. Detection focuses on unexpected writes to profile file paths and on script block logging capturing the profile being loaded.

## What This Dataset Contains

The test appends a `Start-Process calc.exe` line to the SYSTEM-context profile, then immediately spawns a new PowerShell session to confirm it fires. The execution is fully traceable across three channels.

**Security 4688** captures the entire chain:
1. Test framework PowerShell spawned with: `Add-Content $profile -Value "Start-Process calc.exe"` + `powershell -Command exit`
2. `powershell.exe -Command exit` as a new session (the trigger)
3. `calc.exe` launched as the payload

**PowerShell Event ID 4103 (module logging)** records the `Add-Content` cmdlet calls verbatim:
- `Add-Content $profile -Value ""` (blank line spacer)
- `Add-Content $profile -Value "Start-Process calc.exe"`
- `Start-Process -FilePath "calc.exe"` (execution during the triggered session)

**PowerShell Event ID 4104 (script block logging)** captures multiple critical blocks:
- The test framework script block containing the `Add-Content` calls
- A block loaded from `C:\Windows\system32\config\systemprofile\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1` showing the profile content `Start-Process calc.exe`
- The profile execution during the `powershell -Command exit` session: `Start-Process calc.exe`

The profile load path in Event ID 4104 provides direct attribution: `Path: C:\Windows\system32\config\systemprofile\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1`.

## What This Dataset Does Not Contain

- **No Sysmon Event ID 11 tagged for profile modification**: the profile file write is not captured with a T1546.013 rule tag. The sysmon-modular config does not include a specific include rule for writes to PowerShell profile paths.
- **No file creation event for the profile write**: although Sysmon Event ID 11 fires for other file operations in this window, the write to the `.ps1` profile file is not captured. This is a gap for file-monitoring-based detections.
- **No persistence beyond the test window**: the test writes, triggers, and cleans up within its window. There is no second session demonstrating long-lived persistence across a reboot or across different user contexts.
- **No user-context profiles**: the test operates entirely as SYSTEM and targets the SYSTEM profile path. User-specific profile paths (`C:\Users\<user>\Documents\WindowsPowerShell\`) are not touched.

## Assessment

This dataset is valuable because it demonstrates full kill-chain evidence across both the write phase and the execution phase. The combination of PowerShell 4103 (module logging) and 4104 (script block logging) provides the most complete picture: you can see the `Add-Content` call, the profile being loaded, and the payload executing. The explicit profile path in the 4104 `Path:` field is a high-fidelity detection artifact. The gap in Sysmon file creation tagging means file-monitoring-only detections would miss the write. The dataset is strengthened by having actual payload execution (`calc.exe` via `Start-Process`) confirming the persistence mechanism worked.

## Detection Opportunities Present in This Data

1. **PowerShell Event ID 4104 — script block loaded from a profile path**: When Event ID 4104 shows a script block with a `Path:` value matching any known PowerShell profile location, and the block contains suspicious commands, this is a high-confidence persistence indicator.
2. **PowerShell Event ID 4103 — `Add-Content` with `$profile` as the target path**: Module logging records the `Add-Content` cmdlet invocation with the resolved profile path. Alerting on `Add-Content` calls targeting profile file paths catches the write phase.
3. **PowerShell Event ID 4104 — unexpected content in profile script blocks**: Baselining what legitimate profile content looks like (or verifying it is empty) and alerting on unexpected commands such as `Start-Process`, `Invoke-Expression`, or encoded payloads in profile-sourced blocks.
4. **Security 4688 — `powershell.exe -Command exit` or minimal-session PowerShell immediately after a profile-modifying session**: The immediate re-launch of PowerShell to verify the profile fires is a behavioral pattern. In a real attack, a long-lived legitimate session would eventually pick up the persisted payload.
5. **File integrity monitoring on PowerShell profile paths**: Out-of-band or scheduled checks on all known profile locations (SYSTEM, AllUsers, per-user) for unexpected modifications, complementing the event-log detections with a disk-based control.
