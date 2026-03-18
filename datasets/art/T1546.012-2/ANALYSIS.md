# T1546.012-2: Image File Execution Options Injection — IFEO Global Flags

## Technique Context

T1546.012 covers a second IFEO sub-technique beyond the `Debugger` value: the `GlobalFlag` + `SilentProcessExit` combination. Setting `GlobalFlag` to `0x200` (FLG_MONITOR_SILENT_PROCESS_EXIT) on a target executable causes Windows Error Reporting to monitor that process for silent exit. A companion configuration under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\<target>` specifies a `MonitorProcess` to launch when the monitored process exits. The result is that when the target process terminates, the monitoring process specified by the attacker is executed, achieving persistence through a mechanism that avoids both the `Debugger` value and `sdbinst.exe`. This variant is harder to detect than the simple Debugger approach because it involves two separate registry key trees and relies on Windows Error Reporting infrastructure.

## What This Dataset Contains

Three `reg.exe` processes run in rapid succession, all spawned from `cmd.exe`, setting up the full GlobalFlag+SilentProcessExit persistence chain against `notepad.exe`:

Sysmon Event ID 13 shows three registry writes:
- `HKLM\...\Image File Execution Options\notepad.exe\GlobalFlag` = `DWORD (0x00000200)` — tagged T1546.012
- `HKLM\...\SilentProcessExit\notepad.exe\ReportingMode` = `DWORD (0x00000001)` — tagged T1053
- `HKLM\...\SilentProcessExit\notepad.exe\MonitorProcess` = `C:\Windows\System32\cmd.exe` — tagged T1053

The Sysmon Event ID 1 captures all three `reg.exe` command lines with full arguments, as well as the `cmd.exe` orchestrator:

```
"cmd.exe" /c REG ADD "HKLM\...\Image File Execution Options\notepad.exe" /v GlobalFlag /t REG_DWORD /d 512
         & REG ADD "HKLM\...\SilentProcessExit\notepad.exe" /v ReportingMode /t REG_DWORD /d 1
         & REG ADD "HKLM\...\SilentProcessExit\notepad.exe" /v MonitorProcess /d "C:\Windows\System32\cmd.exe"
```

Security 4688 also records all four process creations (`cmd.exe` + three `reg.exe` instances) with command lines.

## What This Dataset Does Not Contain

- **No trigger execution**: the test does not launch and then terminate `notepad.exe`, so there is no downstream `cmd.exe` spawn via WER. The persistence mechanism is established but never exercised.
- **No WerFault.exe execution**: the WER SilentProcessExit monitor runs inside WerFault.exe; without the trigger step, that process never appears here (compare with T1546.012-3 where the trigger fires).
- **Sysmon 13 rule mismatch**: the `SilentProcessExit` registry writes are tagged `T1053` (Scheduled Task) in the sysmon-modular rule set, not T1546.012. This is a rule gap worth noting — the SilentProcessExit mechanism is part of the T1546.012 chain but Sysmon's tagging categorizes it differently.
- The PowerShell channel contains only test framework boilerplate.

## Assessment

This dataset captures the registry side of a multi-key IFEO GlobalFlag attack cleanly. The three Sysmon 13 events plus the corresponding Sysmon 1 / Security 4688 command lines give you both the write telemetry and the invocation chain. The sysmon-modular T1053 tagging for the `SilentProcessExit` keys is a useful illustration of how rule libraries can split attribution across techniques. Detection engineers writing IFEO GlobalFlag rules need to monitor both the `Image File Execution Options` and `SilentProcessExit` key trees together to catch the complete setup. This dataset pairs well with T1546.012-3, which includes the actual trigger execution.

## Detection Opportunities Present in This Data

1. **Sysmon Event ID 13 — `GlobalFlag` value 0x200 under IFEO**: Any write setting `GlobalFlag` to `0x200` (512 decimal) under `Image File Execution Options` is a high-fidelity indicator for the SilentProcessExit persistence setup.
2. **Sysmon Event ID 13 — writes to `SilentProcessExit\*\MonitorProcess`**: The `MonitorProcess` value specifies the attacker-controlled payload. Alert on any write to this path by non-system processes.
3. **Sysmon Event ID 13 — combined IFEO GlobalFlag + SilentProcessExit writes in the same session**: Correlating these two write events within a short time window substantially reduces false positives compared to alerting on either alone.
4. **Sysmon Event ID 1 / Security 4688 — `reg.exe` chained with IFEO and SilentProcessExit arguments**: The three-`reg.exe` burst from a single `cmd.exe` with these specific registry paths is a strong behavioral fingerprint.
5. **Baseline monitoring of `SilentProcessExit` key existence**: The `SilentProcessExit` key tree is absent on a clean Windows 11 installation; any subkeys appearing there warrant investigation.
