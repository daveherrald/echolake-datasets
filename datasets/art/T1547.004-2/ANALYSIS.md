# T1547.004-2: Winlogon Helper DLL — Winlogon Userinit Key Persistence - PowerShell

## Technique Context

T1547.004 (Winlogon Helper DLL) — this test targets the `Userinit` value under the Winlogon registry key. `Userinit` specifies the executable(s) launched by winlogon.exe after a user authenticates, before the desktop shell starts. The default value is `userinit.exe,` (with a trailing comma). By appending an additional executable, an attacker causes their payload to run at every logon of that user before the shell initializes. Like the Shell variant (test -1), the HKCU path requires no elevation; the HKLM path (test -4) requires administrator privileges.

## What This Dataset Contains

The dataset captures a 5-second window on ACME-WS02 during execution of the test modifying the HKCU Winlogon Userinit value.

**PowerShell 4104 and 4103 events** document the test payload:

```powershell
Set-ItemProperty "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" "Userinit" "Userinit.exe, C:\Windows\System32\cmd.exe" -Force
```

Both the `& {…}` wrapped and unwrapped versions appear in 4104 events. The 4103 module logging record captures all parameters: `Path=HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\`, `Name=Userinit`, `Value=Userinit.exe, C:\Windows\System32\cmd.exe`.

**Sysmon Event 1 (ProcessCreate):** `whoami.exe` (T1033) and `powershell.exe` (T1059.001). As with test -1 (Shell variant), `Set-ItemProperty` was used rather than `reg.exe`, so no `reg.exe` process create is present.

**No Sysmon Event 13.** The HKCU Winlogon Userinit path write was not captured by Sysmon registry monitoring, for the same reason as test -1 — a gap in sysmon-modular's coverage of per-user Winlogon values. The registry modification is only evidenced in the PowerShell logs.

**Security events (4688/4689/4703):** Three process-create events (the test framework spawns two PowerShell instances plus whoami), corresponding exits, and a token adjustment.

**Application log Event 16394 (Offline downlevel migration succeeded):** A background Windows component activity — not related to the test.

The 39 PowerShell events are predominantly test framework boilerplate.

## What This Dataset Does Not Contain

- **No Sysmon Event 13.** Same gap as test -1 — HKCU Winlogon writes not captured by Sysmon registry monitoring in this configuration.
- **No logon telemetry.** The Userinit modification has no effect until a user logs in; no logon occurred during collection.
- **No `cmd.exe` spawn from Userinit.** The payload was placed but never triggered.
- **No Security 4657.** Registry auditing not enabled.

## Assessment

This dataset is structurally near-identical to T1547.004-1 (Shell variant) with the key difference being the `Userinit` value name instead of `Shell`. The same Sysmon detection gap applies: the registry write is visible only in PowerShell logs. This consistency across tests -1 and -2 confirms that the sysmon-modular configuration has a systematic gap for HKCU Winlogon value modifications, regardless of which specific value name is targeted.

The Userinit path is sometimes overlooked in detection rules that focus primarily on the Shell value. A defender examining this dataset alongside test -1 would recognize that both HKCU Winlogon subkey values (`Shell` and `Userinit`) require explicit detection rules, and that PowerShell logging is the compensating control here.

The Application log Event 16394 (offline downlevel migration) is unrelated background noise from a Windows Update or licensing component.

## Detection Opportunities Present in This Data

- **PowerShell 4104 / 4103:** `Set-ItemProperty` targeting `HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\` with `Name=Userinit` and any value other than `userinit.exe,` (or the default path) is a high-confidence indicator.
- **Value pattern:** The `Userinit.exe, C:\Windows\System32\cmd.exe` format — a comma-separated list appending an executable — is the characteristic modification pattern. Any non-standard secondary executable in this value warrants investigation.
- **PowerShell 4103 module logging:** `CommandInvocation(Set-ItemProperty)` with Winlogon path and Userinit name is detectable even without 4104 script block logging.
- **Gap validation:** This dataset can be used to verify whether a Sysmon deployment catches writes to `HKU\*\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit` — the absence of Event 13 here indicates a monitoring blind spot.
- **Correlated with test -1:** Detections should cover both `Shell` and `Userinit` values in both HKCU and HKLM Winlogon paths.
