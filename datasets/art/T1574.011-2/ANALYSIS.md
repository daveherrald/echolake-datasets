# T1574.011-2: Services Registry Permissions Weakness — Services Registry Permissions Weakness - Service ImagePath Change with reg.exe

## Technique Context

T1574.011 (Hijack Execution Flow: Services Registry Permissions Weakness) exploits writable service registry keys to redirect a service to an attacker-controlled binary. Where T1574.011-1 focuses on reconnaissance (finding weak permissions), this test demonstrates the exploitation step: directly modifying a service's `ImagePath` registry value using `reg.exe` to point to an attacker-chosen executable.

`reg.exe` is used rather than `sc.exe` or PowerShell cmdlets because it directly writes registry values, bypassing the Service Control Manager's validation logic. This approach works even without `SeServiceLogonRight` or SC write access, provided the attacker has raw registry write access to the service key.

## What This Dataset Contains

The dataset captures 85 events across Sysmon (36), Security (13), PowerShell (34), System (1), and WMI (1) logs collected over approximately 6 seconds on ACME-WS02.

**The ImagePath modification is fully captured:**

Sysmon Event 1 shows the attack command:
- `cmd.exe /c reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\calcservice" /f /v ImagePath /d "%windir%\system32\calc.exe"`
- `reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\calcservice" /f /v ImagePath /d "C:\Windows\system32\calc.exe"` — the expanded command

Sysmon Event 13 (Registry Value Set) captures the actual registry write:
- `TargetObject: HKLM\System\CurrentControlSet\Services\calcservice\ImagePath`
- `Details: C:\Windows\system32\cmd.exe` — the value written (notably `cmd.exe`, not `calc.exe` as in the command, suggesting the service existed with `cmd.exe` or this was a pre-existing test service)

System Event 7040 records:
- `The start type of the Background Intelligent Transfer Service service was changed from auto start to demand start.` — this is background OS activity (Windows Update adjusting BITS), not related to the attack, but present in the capture window as real environmental noise.

WMI Event 5858 (WMI Error) records a WMI query failure from `NT AUTHORITY\SYSTEM` — routine background WMI activity unrelated to the attack.

Security Event 4688 records `cmd.exe` and `reg.exe` process creation with full command lines.

## What This Dataset Does Not Contain (and Why)

**No service restart.** After modifying the `ImagePath`, a service restart would be needed to trigger execution of the new binary. This test only performs the registry modification; no `sc start` or service restart follows in the capture window.

**No execution of the redirected binary.** Since the service did not restart, `cmd.exe` (the new `ImagePath` value) was not launched as a service process. No new process creation from the Service Control Manager appears.

**No Defender block.** Unlike other tests in this group, registry writes via `reg.exe` are not blocked by Defender; the write succeeded (exit code `0x0`). The modification itself is not detectable as malicious by AV — it is a legitimate registry operation.

**Environmental noise present.** The System 7040 (BITS service start type change) and WMI 5858 events are genuine background system activity captured during the test window, not attack artifacts. This reflects real-world log conditions where benign events occur concurrently with malicious activity.

## Assessment

This dataset provides clean telemetry for the exploitation phase of a Services Registry Permissions Weakness attack. The `reg.exe` command line, the Sysmon Event 13 registry write to an `ImagePath` value, and the Security Event 4688 process creation form a tight correlated detection opportunity. Unlike many tests in this group where Defender blocks the attack, this registry modification succeeded — making it a reliable positive example of the technique's execution artifacts. The environmental noise (System 7040, WMI 5858) adds realism to the dataset.

## Detection Opportunities Present in This Data

- **Sysmon Event 13**: `HKLM\System\CurrentControlSet\Services\calcservice\ImagePath` modified by `reg.exe` — direct registry modification of a service `ImagePath` is the core attack action and a high-confidence indicator.
- **Sysmon Event 1**: `reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\..." /v ImagePath /d ...` — explicit `reg.exe` command modifying a service ImagePath is a strong detection signal.
- **Security Event 4688**: `reg.exe` with service registry `ImagePath` modification argument — correlates with Sysmon and provides Security log coverage.
- **System Event 7040**: BITS service start type change — environmental background event; useful as a contrast to the attack event for false positive analysis.
- **WMI Event 5858**: Background WMI error — additional environmental noise demonstrating concurrent system activity.
- **Correlation opportunity**: `cmd.exe` creating `reg.exe` which modifies a service `ImagePath` — the full process chain from Security 4688 + Sysmon 1 + Sysmon 13 provides a correlated multi-source detection.
