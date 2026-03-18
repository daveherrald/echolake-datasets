# T1562.001-31: Disable or Modify Tools — Tamper with Windows Defender ATP using Aliases - PowerShell

## Technique Context

MITRE ATT&CK T1562.001 (Disable or Modify Tools) includes modifying security software configuration to reduce its effectiveness. Windows Defender exposes configuration through the `Set-MpPreference` PowerShell cmdlet, which accepts alias flags for its parameters. This test uses abbreviated parameter aliases (`-drtm`, `-dbm`, `-dscrptsc`, `-dbaf`) to enable behaviors that weaken real-time protection: disabling real-time monitoring, behavior monitoring, script scanning, and block-at-first-seen. This alias-based approach has been observed as a technique to obfuscate the intent of a command from defenders who may only recognize the full parameter names.

## What This Dataset Contains

The dataset captures 6 seconds of telemetry from ACME-WS02 during the Atomic Red Team execution of `Set-MpPreference` with Defender-weakening aliases.

**Security 4688 — Process creation, test framework launches the attack:**
```
New Process Name: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Process Command Line: "powershell.exe" & {Set-MpPreference -drtm $True
Set-MpPreference -dbm $True
Set-MpPreference -dscrptsc $True
Set-MpPreference -dbaf $True}
```

**PowerShell 4104 — Script block logging captures the exact invocation:**
```
& {Set-MpPreference -drtm $True
Set-MpPreference -dbm $True
Set-MpPreference -dscrptsc $True
Set-MpPreference -dbaf $True}
```

The four abbreviated aliases expand as:
- `-drtm` → `DisableRealtimeMonitoring`
- `-dbm` → `DisableBehaviorMonitoring`
- `-dscrptsc` → `DisableScriptScanning`
- `-dbaf` → `DisableBlockAtFirstSeen`

**Security 4703 — Token right adjustment:**
Multiple events show PowerShell enabling `SeTakeOwnershipPrivilege` and `SeLoadDriverPrivilege` for the SYSTEM session. These privilege adjustments occur as the Defender configuration changes are applied and are logged by the token right adjustment audit policy.

**Sysmon EID 1 — Process creates:**
`whoami.exe` (ART identity check) and the child `powershell.exe` carrying the `Set-MpPreference` commands.

**Sysmon EID 7 — Image loads:** Standard PowerShell runtime and Defender DLLs load into the process context.

## What This Dataset Does Not Contain (and Why)

**Confirmation that Defender was actually weakened** — `Set-MpPreference` is callable but Windows Defender Tamper Protection (enabled on this host) prevents the preference changes from taking effect on a managed device. The dataset does not contain registry modifications or Defender state-change events that would indicate successful weakening.

**WMI or registry events showing the change committed** — No Sysmon EID 13 (registry value set) in the Defender preference key (`HKLM\SOFTWARE\Microsoft\Windows Defender`) appears, because Tamper Protection blocked the write.

**PowerShell errors** — No 4100 error events appear, which is notable. `Set-MpPreference` returns success even when Tamper Protection silently rejects the change. The absence of an error does not confirm the changes were applied.

**Sysmon EID 12/13 (registry create/modify)** — No registry telemetry for the Defender configuration hive is present, consistent with Tamper Protection preventing the modification.

## Assessment

This is a **tamper protection blocked** dataset with clean command-line evidence. The four `Set-MpPreference` calls with abbreviated aliases are captured in full in both Security 4688 (parent command line) and PowerShell 4104 (script block). Tamper Protection on this host silently blocked the changes without producing a PowerShell error, illustrating an important detection gap: the absence of a 4100 error does not mean the technique succeeded. The token right adjustment events (4703) are ambient privilege noise from the SYSTEM context executing configuration calls, not evidence of privilege escalation. The 4103 module logging for this test shows only the test framework `Set-ExecutionPolicy` boilerplate; `Set-MpPreference` does not emit module pipeline output in this configuration.

## Detection Opportunities Present in This Data

- **`Set-MpPreference` with Defender-weakening parameters** (Security 4688 / PowerShell 4104): Any combination of `Set-MpPreference` with parameters containing `Disable` or their abbreviated aliases (`-drtm`, `-dbm`, `-dscrptsc`, `-dbaf`) should alert. The full parameter names are more commonly detected; the alias forms are worth adding to detection logic.
- **Script block logging** (EID 4104): The four-call pattern across consecutive lines in a single script block is distinctive. Detections should normalize both abbreviated and full parameter names.
- **PowerShell command line containing `Set-MpPreference`** (Security 4688): Even without script block logging, the command line in the 4688 event contains the full command text and is queryable via process creation auditing.
- **Absence of 4100 error as a post-confirmation gap**: Analysts should not rely on error events to confirm that `Set-MpPreference` changes were blocked; use registry auditing or Defender state monitoring as the authoritative source.
