# T1546.012-1: Image File Execution Options Injection — IFEO Add Debugger

## Technique Context

T1546.012 (Image File Execution Options Injection) abuses the Windows Image File Execution Options (IFEO) registry key to intercept process launches. When a `Debugger` value is set under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<target.exe>`, Windows launches the specified debugger instead of (or before) the target executable. Attackers use this to redirect execution of legitimate system binaries to their payloads, achieving both persistence (the payload runs whenever the target is launched) and, if the target runs at elevated privilege, privilege escalation. This technique is notable for its use against accessibility binaries (sethc.exe, utilman.exe) to obtain SYSTEM shells from the lock screen — a favored lateral movement path.

## What This Dataset Contains

The test sets a `Debugger` value against `calc.exe` via `cmd.exe` spawning `reg.exe`. The full execution chain is visible:

Sysmon Event ID 1 (ProcessCreate) captures both the cmd.exe and reg.exe invocations:
- `"cmd.exe" /c REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\calc.exe" /v Debugger /d "C:\Windows\System32\cmd.exe"`
- `REG ADD "HKLM\...\Image File Execution Options\calc.exe" /v Debugger /d "C:\Windows\System32\cmd.exe"`

Sysmon Event ID 13 (Registry Value Set) confirms the write, tagged `technique_id=T1546.012,technique_name=Image File Execution Options Injection`:
- `TargetObject: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\calc.exe\Debugger`
- `Details: C:\Windows\System32\cmd.exe`

The Security channel (4688) captures `whoami.exe`, the test framework outer `powershell.exe`, `cmd.exe`, and `reg.exe` process creations with full command lines.

## What This Dataset Does Not Contain

- **No IFEO trigger execution**: the test does not invoke `calc.exe` after setting the debugger, so there is no event showing `cmd.exe` spawned under the IFEO interception. A full-lifecycle dataset would show the intercepted launch.
- **No accessibility binary targeting**: this test uses `calc.exe` as the target, which is a less sensitive target than the accessibility binaries typically used in real-world attacks. Rules focused on sethc.exe, utilman.exe, narrator.exe, or osk.exe would not fire here.
- **Sysmon ProcessCreate filtering**: only `cmd.exe` and `reg.exe` are caught by Sysmon Event ID 1 (matching `T1059.003` and `T1012` include rules respectively). The outer test framework PowerShell is only in Security 4688.
- The PowerShell channel contains only standard test framework boilerplate (`Set-StrictMode`, `Set-ExecutionPolicy -Bypass`). No substantive PowerShell content for this test.

## Assessment

This is a high-quality, concise dataset for IFEO Debugger detection. The Sysmon Event ID 13 with accurate T1546.012 tagging is the primary detection artifact. The full `reg.exe` command line in both Sysmon Event ID 1 and Security 4688 provides layered corroboration. The dataset is suitable for validating alerts against IFEO Debugger key writes and for testing `reg.exe`-based registry modification detections. It would be strengthened by including a trigger step showing `cmd.exe` actually spawning under IFEO context, and by testing against a higher-value target such as an accessibility binary.

## Detection Opportunities Present in This Data

1. **Sysmon Event ID 13 — write to IFEO `\Debugger`**: Alert on any `SetValue` to `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*\Debugger`. This is a high-fidelity indicator; there is minimal legitimate use.
2. **Sysmon Event ID 1 / Security 4688 — `reg.exe` writing IFEO Debugger key**: Detect `reg.exe` with a command line matching `Image File Execution Options.*Debugger` in any invocation context.
3. **Security 4688 — `cmd.exe` parent of `reg.exe` with IFEO-related arguments**: The `cmd.exe` → `reg.exe` process chain with IFEO-targeting arguments is a reliable pattern.
4. **IFEO key modification for high-sensitivity targets**: Additional logic to specifically alert when the target executable is an accessibility binary (sethc.exe, utilman.exe, narrator.exe) or a security tool elevates this to critical severity.
5. **Baseline comparison — unexpected IFEO Debugger values**: Periodic scanning of all `Image File Execution Options` subkeys for unexpected `Debugger` values, compared against an OS baseline, catches both this technique and variants using PowerShell or other registry writers.
