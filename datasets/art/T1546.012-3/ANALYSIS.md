# T1546.012-3: Image File Execution Options Injection — GlobalFlags in Image File Execution Options (With Trigger)

## Technique Context

T1546.012 via `GlobalFlag` and `SilentProcessExit` achieves persistence through Windows Error Reporting (WER): the attacker sets `GlobalFlag=0x200` on a target executable, configures `SilentProcessExit\<target>\MonitorProcess` to point to a payload, then whenever the target exits cleanly, `WerFault.exe` launches the monitor process. This test goes further than T1546.012-2 by also triggering the mechanism — running the monitored process (`whoami.exe`) so that WER fires and executes the specified payload (`cmd.exe /c calc.exe`). This is the only dataset in this T1546.012 series that contains end-to-end execution: setup through payload delivery.

## What This Dataset Contains

The setup phase uses PowerShell's `Set-ItemProperty` to write the registry keys (three Sysmon Event ID 13 writes):
- `HKLM\...\Image File Execution Options\whoami.exe\GlobalFlag` = `DWORD (0x00000200)` — tagged T1546.012
- `HKLM\...\SilentProcessExit\whoami.exe\ReportingMode` = `DWORD (0x00000001)`
- `HKLM\...\SilentProcessExit\whoami.exe\MonitorProcess` = `cmd.exe /c calc.exe`

The Sysmon Event ID 1 PowerShell process create confirms registry writes via PowerShell directly (not `reg.exe`):
```
"powershell.exe" & {$Name = "GlobalFlag" ...
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\whoami.exe" ...
```

The trigger phase is fully captured. After `whoami.exe` (PID 1524) is launched and exits, Sysmon shows:
- Event ID 1: `WerFault.exe` with arguments `-s -t 4552 -i 1524 -e 1524 -c 0` (a silent process exit report for PID 1524)
- Event ID 10: `WerFault.exe` accessing the `whoami.exe` process (tagged T1003/Credential Dumping by sysmon-modular's DLL injection rule)
- Event ID 1: `cmd.exe` with command line `cmd.exe /c calc.exe` — the MonitorProcess payload executing
- Event ID 1: `calc.exe` launched as the final payload

The Security channel (4688) captures the same `cmd.exe /c calc.exe` execution, with `WerFault.exe` as the parent process.

The Application log includes an event 3000 entry related to WER activity.

## What This Dataset Does Not Contain

- **No WerFault.exe → payload relationship in Sysmon 1**: Sysmon's ProcessCreate for `cmd.exe /c calc.exe` does not show `WerFault.exe` as the parent in the Message field; the parent relationship is confirmed through the Security 4688 event instead, where the parent process context is more explicit.
- **No Sysmon Event ID 12 (key creation)**: only SetValue (Event ID 13) is present. Key creation events that fired when the `GlobalFlag` and `SilentProcessExit` keys were first created are absent.
- **Sysmon ProcessCreate filtering**: the outer test framework PowerShell is not in Sysmon Event ID 1; only the test-executing child PowerShell and subsequent LOLBins appear.

## Assessment

This is the strongest dataset in the T1546.012 series for detection engineering because it demonstrates the full kill chain: registry setup → monitored process execution → WerFault.exe activation → payload delivery. The `WerFault.exe` → `cmd.exe` → `calc.exe` process chain is directly observable in the Security channel. The Sysmon 13 registry writes and Security 4688 chain together to form a complete narrative. Detection rules can be tested against both the setup phase (registry writes) and the execution phase (WerFault.exe spawning unexpected children). This is particularly useful because WerFault.exe is normally a terminal process — it should never have children.

## Detection Opportunities Present in This Data

1. **Sysmon Event ID 13 — IFEO GlobalFlag set to 0x200**: Alert when `GlobalFlag` under any `Image File Execution Options` subkey is set to `0x200` by any process other than a known software installer.
2. **Sysmon Event ID 1 / Security 4688 — `WerFault.exe` spawning unexpected children**: `WerFault.exe` should not create child processes such as `cmd.exe`, `powershell.exe`, or other shells. Any such child is a high-confidence indicator of SilentProcessExit abuse.
3. **Security 4688 — `cmd.exe /c calc.exe` (or other payloads) with `WerFault.exe` parent**: Correlate process creation events where the parent is `WerFault.exe` and the child is a shell or scripting engine.
4. **Sysmon Event ID 10 — `WerFault.exe` accessing a monitored process**: The process access event where WerFault opens the exiting process with suspicious access rights confirms the WER mechanism fired.
5. **Combined detection — `SilentProcessExit\*\MonitorProcess` write followed by WerFault.exe execution**: Link the registry write (setup) with WerFault.exe child spawning (trigger) using process GUIDs or time correlation for a high-fidelity compound rule.
6. **Security 4688 — PowerShell using `Set-ItemProperty` against `Image File Execution Options`**: The PowerShell-direct registry write method (as opposed to `reg.exe`) is a variant that `reg.exe`-focused rules will miss; script block logging via 4104 provides coverage here.
