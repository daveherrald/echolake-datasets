# T1547.004-3: Winlogon Helper DLL — Winlogon Notify Key Logon Persistence - PowerShell

## Technique Context

T1547.004 (Winlogon Helper DLL) — this test exercises the Winlogon Notification Package mechanism, a legacy but still-functional extension point. The `Winlogon\Notify` registry subkey allows DLLs to register as notification handlers for Winlogon events (logon, logoff, startup, shutdown). When registered, the DLL is loaded into winlogon.exe's process space and its exported function (specified in the `Logon` value) is called on each corresponding event. This mechanism predates modern Windows credential provider architecture but persists in the registry schema. It requires administrator privileges to write to the HKCU path shown here, though a real attacker would more likely use HKLM for greater persistence scope.

## What This Dataset Contains

The dataset captures a 5-second window on ACME-WS02 during execution of the ART test that creates a Winlogon Notify subkey.

**PowerShell 4104 events** capture the full test payload:

```powershell
New-Item "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\AtomicRedTeam" -Force
Set-ItemProperty "HKCU:\...\Notify\AtomicRedTeam" "DllName" "C:\Windows\Temp\atomicNotificationPackage.dll" -Type ExpandString -Force
Set-ItemProperty "HKCU:\...\Notify\AtomicRedTeam" "Logon" "AtomicTestFunction" -Force
Set-ItemProperty "HKCU:\...\Notify\AtomicRedTeam" "Impersonate" 1 -Type DWord -Force
```

This creates a complete notification package registration: DLL path, event handler function name, and the Impersonate flag (allowing the notification handler to run in the logged-on user's security context).

**Sysmon Event 1 (ProcessCreate):** `whoami.exe` (T1033) and `powershell.exe` (T1059.001). As with tests -1 and -2, `Set-ItemProperty` and `New-Item` were used via the PowerShell registry provider.

**No Sysmon Event 13.** The Winlogon Notify subkey creation and value writes were not captured by Sysmon registry monitoring. This is the third consecutive HKCU Winlogon-area path (after Shell and Userinit) where Sysmon monitoring has a gap. The pattern across tests -1, -2, and -3 confirms that the sysmon-modular configuration does not have rules covering HKCU Winlogon subpaths at this depth.

**Security events (4688/4689/4703):** Two process-create events, exits, and a token adjustment. Minimal — no `reg.exe` spawned.

The 37 PowerShell events are predominantly test framework boilerplate.

## What This Dataset Does Not Contain

- **No Sysmon Event 13.** Consistent with tests -1 and -2 — HKCU Winlogon subpath writes not captured by Sysmon registry monitoring.
- **No DLL file creation.** `atomicNotificationPackage.dll` is referenced in the registry value but was not created during this test. The DLL does not exist on disk — this is a registry-only operation in the ART test.
- **No winlogon.exe loading the DLL.** No logon event occurred.
- **No Security 4657.** Registry auditing not enabled.
- **No Application or System log events.** Unlike the T1547.003 tests, there are no service restarts here that would generate side-effect events.

## Assessment

This dataset demonstrates persistence via the Winlogon Notify mechanism — a less commonly tested extension point that is sometimes overlooked in detection rule sets. The technique leaves a characteristic registry structure (`Notify\<name>` with `DllName`, `Logon`, and `Impersonate` values) that is straightforward to detect if the path is monitored.

The three-test pattern of Sysmon Event 13 absence for HKCU Winlogon paths (tests -1, -2, -3) is the most analytically interesting finding across this group. Defenders using only Sysmon for registry monitoring would have no direct evidence of these modifications; PowerShell logging is the sole visibility channel for all three.

The `Notify` subkey mechanism is a legacy path that Windows still honors. The `Impersonate` flag in the registration is a detail worth noting: a notification package with `Impersonate=1` runs in the user's token, while `Impersonate=0` (or absent) runs in the SYSTEM context.

## Detection Opportunities Present in This Data

- **PowerShell 4104:** Script blocks creating `Winlogon\Notify\*` subkeys and setting `DllName`, `Logon`, and `Impersonate` values. The combination of `New-Item` + `Set-ItemProperty` targeting `Winlogon\Notify\` is high-confidence.
- **Registry monitoring (if coverage extended):** Writes to `HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\*\DllName` — the creation of any new subkey under `Notify\` is anomalous on modern Windows workstations where the Notify mechanism is rarely used legitimately.
- **DLL path heuristics:** A `DllName` pointing to `C:\Windows\Temp\` or any world-writable location (rather than `C:\Windows\System32\`) is a strong indicator regardless of the registry path context.
- **Gap validation (tests -1 through -3):** The consistent absence of Sysmon Event 13 across all three HKCU Winlogon path variants provides evidence that Sysmon's registry coverage for per-user Winlogon values requires explicit rule additions in sysmon-modular.
