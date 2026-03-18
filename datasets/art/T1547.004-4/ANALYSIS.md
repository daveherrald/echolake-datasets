# T1547.004-4: Winlogon Helper DLL — Winlogon HKLM Shell Key Persistence - PowerShell

## Technique Context

T1547.004 (Winlogon Helper DLL) — this test targets the `Shell` value under `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon`, the machine-wide version of the Winlogon Shell key. Unlike test -1 (HKCU), modifying the HKLM path requires administrator or SYSTEM privileges and affects all users who log on to the machine. This is the higher-impact variant: a malicious executable appended to the HKLM Shell value will launch for every user logon, not just the specific user whose HKCU was modified.

## What This Dataset Contains

The dataset captures a 5-second window on ACME-WS02 with telemetry across five log sources (the most diverse in the T1547.004 group).

**PowerShell 4104 and 4103 events** document the test payload:

```powershell
Set-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" "Shell" "explorer.exe, C:\Windows\System32\cmd.exe" -Force
```

Both wrapped and unwrapped versions appear in 4104. The 4103 module event records `CommandInvocation(Set-ItemProperty)` with `Path=HKLM:\...`, `Name=Shell`, `Value=explorer.exe, C:\Windows\System32\cmd.exe`.

**Sysmon Event 13 (RegistrySetValue)** — this test *does* generate a Sysmon 13, in contrast to tests -1, -2, and -3:

```
RuleName: technique_id=T1547.004,technique_name=Winlogon Helper DLL
TargetObject: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell
Details: explorer.exe, C:\Windows\System32\cmd.exe
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

The Sysmon-modular configuration has a named T1547.004 rule for the HKLM Winlogon path but not for the equivalent HKCU paths (tests -1, -2, -3). This is the key differentiator: HKLM Winlogon shell monitoring is covered; HKCU Winlogon monitoring is not.

There is also a separate Sysmon 13 event from `svchost.exe` writing to `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask\Index` — a pre-existing scheduled task being touched by the Windows Software Protection service, unrelated to the test.

**Sysmon Event 1 (ProcessCreate):** `whoami.exe` (T1033) and `powershell.exe` (T1059.001).

**Security events (4688/4689/4703):** Three process-create events, exits, and a token adjustment. All under SYSTEM.

**Application log Event 16384 (Successfully scheduled Software Protection service for re-start):** Background Windows licensing activity, unrelated to the test.

**Task Scheduler log Event 140 (User updated Task Scheduler task `\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask`):** A background Windows maintenance activity. The same task whose registry key appeared in the unrelated Sysmon 13 event above — confirming this is a legitimate background operation coincidentally present during the test window.

## What This Dataset Does Not Contain

- **No logon-triggered payload execution.** No logon occurred; `cmd.exe` was placed in the Shell value but never triggered.
- **No Sysmon Event 7 (ImageLoad) for the payload DLL.** There is no DLL involved in this test — it is a pure registry value modification.
- **No Security 4657.** Registry auditing not enabled.
- **No network or DNS events.** `cmd.exe` is a benign local payload.

## Assessment

This dataset is the most detection-rich of the four T1547.004 tests because it is the only one where Sysmon Event 13 fires with a named T1547.004 rule. The contrast with tests -1, -2, and -3 is analytically significant: the sysmon-modular configuration monitors HKLM Winlogon Shell but not HKCU Winlogon Shell/Userinit/Notify. This asymmetry means that HKLM-based Winlogon persistence (privileged, higher-impact) is detected via Sysmon, while HKCU-based persistence (lower-privilege, user-specific) has Sysmon blind spots and depends on PowerShell logging for detection.

Windows Defender did not block the `HKLM` shell modification using `cmd.exe` as the secondary payload. The Application and TaskScheduler events (16384 and 140) are authentic background noise from the Windows environment, not test artifacts — they demonstrate real-world co-occurrence of unrelated system events within a short collection window.

## Detection Opportunities Present in This Data

- **Sysmon Event 13 (tagged T1547.004):** Write to `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell` appending any executable beyond `explorer.exe`. The sysmon-modular rule fires specifically on this path — a named detection rule exists.
- **PowerShell 4104 / 4103:** Same detection opportunity as tests -1 through -3 — `Set-ItemProperty` with HKLM Winlogon Shell path and a comma-separated value are detectable from logs.
- **Value content heuristic:** `explorer.exe, <anything>` in the Winlogon Shell value — the comma-separated format is the canonical malicious modification pattern for both HKCU and HKLM Winlogon Shell.
- **HKLM vs. HKCU coverage gap:** The contrast across the four T1547.004 datasets makes a strong argument for adding explicit Sysmon rules for `HKU\*\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell` (HKCU) to match the existing HKLM coverage.
- **Background noise filtering:** Application Event 16384 and TaskScheduler Event 140 for SoftwareProtectionPlatform are reliable background events that can be safely filtered in detections targeting this technique's registry modification.
