# T1547.004-1: Winlogon Helper DLL — Winlogon Shell Key Persistence - PowerShell

## Technique Context

T1547.004 (Winlogon Helper DLL) covers persistence through modification of Winlogon registry values. The Windows logon process (winlogon.exe) reads several registry values during logon to load helper components. The `Shell` value under `HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon` specifies the interactive shell; by appending an executable to `explorer.exe` in this value, an attacker causes their payload to launch alongside the desktop shell on logon. The HKCU variant (this test) requires no elevated privileges — any user can set it in their own hive. This makes it accessible to unprivileged persistence scenarios, though here it executes under SYSTEM.

## What This Dataset Contains

The dataset captures a 5-second window on ACME-WS02 during execution of the ART test that modifies the HKCU Winlogon Shell value.

**PowerShell 4104 and 4103 events** fully document the test:

```powershell
Set-ItemProperty "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" "Shell" "explorer.exe, C:\Windows\System32\cmd.exe" -Force
```

The 4103 module logging event records `CommandInvocation(Set-ItemProperty)` with all parameters: path, name (`Shell`), and value (`explorer.exe, C:\Windows\System32\cmd.exe`). Both the wrapped (`& {...}`) and unwrapped versions of the script block appear in 4104 events — a consistent artifact of how ART wraps test payloads.

**Sysmon Event 1 (ProcessCreate):** `whoami.exe` (T1033) and `powershell.exe` (T1059.001) — the ART test framework identity check and the PowerShell instance executing the test. No `reg.exe` — the modification was made via PowerShell's registry provider (`Set-ItemProperty`), not the command-line registry tool.

**No Sysmon Event 13.** This is the notable absence: the Sysmon-modular configuration's ProcessCreate include filter matched `powershell.exe` (T1059.001 rule), but the registry write via `Set-ItemProperty` to the HKCU Winlogon Shell path did not generate a Sysmon EventID 13. This likely reflects a gap in the sysmon-modular registry monitoring rules for the HKCU `Winlogon\Shell` path (HKCU is scoped per-user; monitoring all HKU paths for this value can be noisy).

**Security events (4688/4689/4703):** Two process-create events and corresponding exits plus a token adjustment, all under SYSTEM.

The 39 PowerShell events are heavily dominated by test framework boilerplate — the meaningful content is concentrated in 3-4 events.

## What This Dataset Does Not Contain

- **No Sysmon Event 13 (RegistrySetValue).** The HKCU Winlogon Shell modification was not captured by Sysmon despite the write occurring. This is a significant detection gap: the only log evidence of the registry modification comes from PowerShell script block logging, not from Sysmon registry monitoring.
- **No logon event triggering the payload.** No 4624 or winlogon-initiated process launch occurred.
- **No `cmd.exe` execution as the payload.** The appended payload was never triggered during the collection window.
- **No Security 4657.** Registry auditing not enabled.

## Assessment

This dataset demonstrates a meaningful blind spot: a Winlogon Shell persistence write to HKCU was not captured by Sysmon's registry monitoring despite Sysmon being fully configured with sysmon-modular. The only telemetry of the actual registry modification comes from PowerShell script block logging (4104/4103). This pattern — where PowerShell log coverage compensates for a Sysmon registry monitoring gap — highlights the importance of multi-source collection in detection architectures.

Windows Defender did not block the operation. The technique completed successfully — `cmd.exe` is a legitimate Windows binary, and appending it to the Shell value using PowerShell's registry cmdlet is a low-profile approach.

## Detection Opportunities Present in This Data

- **PowerShell 4104 / 4103:** Script blocks or module invocations targeting `HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\` with a `Shell` value containing anything beyond `explorer.exe` are high-confidence persistence indicators. This is the only log source in this dataset that captures the write.
- **PowerShell 4103:** `Set-ItemProperty` with `Name=Shell` and `Value` containing a comma-separated executable list (the `explorer.exe, <payload>` pattern) is detectable.
- **Sysmon Event 1:** `powershell.exe` spawned under SYSTEM with no interactive parent, immediately followed by a process exit, is consistent with scripted registry manipulation even without the Event 13 confirming the write.
- **Gap identification:** This dataset is useful for testing whether Sysmon registry monitoring rules cover `HKU\*\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell` — if Event 13 does not appear, the rule set has a blind spot for this persistence path.
