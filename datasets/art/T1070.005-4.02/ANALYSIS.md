# T1070.005-4: Network Share Connection Removal — Disable Administrative Share Creation at Startup

## Technique Context

Windows automatically recreates administrative shares (C$, ADMIN$, IPC$) each time the LanmanServer service starts, regardless of whether they were manually deleted. To persistently suppress their creation, an attacker must write registry values to the LanmanServer service parameters: `AutoShareServer` (which controls C$ and ADMIN$ on server SKUs) and `AutoShareWks` (which controls C$ and ADMIN$ on workstation SKUs), both set to `0` under `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`.

This technique is distinct from simply deleting the shares at runtime: it persists across reboots. An attacker might use this to prevent incident responders from using administrative shares for lateral access to a compromised host, or to prevent SIEM/EDR tools that use administrative shares for deployment or log collection from functioning.

The test uses `reg.exe` via `cmd.exe` to set both registry values, then uses the cleanup phase to delete those same values (restoring the default behavior). Both write and delete operations are fully captured.

Neither Defender nor any endpoint controls block this registry modification — it is a standard registry write to a LanmanServer parameters key.

## What This Dataset Contains

The technique execution produces a rich set of events across process creation and registry modification channels.

Security EID 4688 records the full `cmd.exe` invocation with command line: `"cmd.exe" /c reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareServer /t REG_DWORD /d 0 /f & reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareWks /t REG_DWORD /d 0 /f`. Both registry additions are in a single command using `&` to chain two `reg.exe` calls. Separate EID 4688 entries record each `reg.exe` invocation:
- `reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareServer /t REG_DWORD /d 0 /f`
- `reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareWks /t REG_DWORD /d 0 /f`

Sysmon EID 13 (registry value set) captures the actual registry modifications:
- `HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters\AutoShareServer = DWORD (0x00000000)`
- `HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters\AutoShareWks` (implied by the second reg.exe call)

Sysmon EID 12 (registry object create/delete) records the cleanup phase, showing `EventType=DeleteValue` for both:
- `HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters\AutoShareServer`
- `HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters\AutoShareWks`

The cleanup phase Security EID 4688 records `cmd.exe` and `reg.exe` invocations for the delete operations: `reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareServer /f` and the corresponding `AutoShareWks` deletion.

Sysmon EID 1 captures all `reg.exe` invocations with `technique_id=T1083,technique_name=File and Directory Discovery` tags — a Sysmon rule artifact, not an accurate technique attribution. The actual technique is T1070.005.

Sysmon EID 11 records the PowerShell startup profile cache write at `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-Interactive`.

The dataset contains 137 total events: 104 PowerShell, 8 Security, and 26 Sysmon (which includes EID 1, 7, 10, 11, 12, 13, 17).

## What This Dataset Does Not Contain

No administrative share deletion events are present. This test modifies the registry to prevent share recreation — it does not delete the existing C$, ADMIN$, or IPC$ shares. If the system were rebooted after this test (which it was not), the shares would not be recreated. The actual runtime share state change is not captured here.

There are no Security log events for the registry modification itself (such as Security EID 4657 for registry value modification). Registry object access auditing was not enabled. The registry modification evidence comes entirely from Sysmon EID 12 and EID 13.

No network events, SMB-level telemetry, or LanmanServer service restart events are present. The new registry values would only take effect after a service restart or system reboot, neither of which occurred during this test.

No Defender events or behavioral alerts are present.

## Assessment

This dataset provides complete visibility into both the technique execution (registry writes setting AutoShareServer and AutoShareWks to 0) and the cleanup (registry value deletions). The registry modification evidence is directly recorded in Sysmon EID 13, with the exact key paths and values, and the process creation evidence in Security EID 4688 provides the command lines showing the `reg.exe` writes.

Compared to the defended variant (20 Sysmon, 15 Security, 25 PowerShell), the undefended run has more events (26 Sysmon, 8 Security, 104 PowerShell). The substantially higher PowerShell EID 4104 count in the undefended run (104 vs. 25) reflects the ART test framework behavior seen across this series. The Security and Sysmon event counts are similar.

This dataset is particularly useful for detection engineering because it captures both the write and the delete of the target registry values, providing examples of both `EventType=SetValue` (EID 13) and `EventType=DeleteValue` (EID 12) for the same registry path.

## Detection Opportunities Present in This Data

**Sysmon EID 13 writing `AutoShareServer` or `AutoShareWks` to 0:** The registry modification is directly captured with the exact key path `HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters\AutoShareServer` and value `DWORD (0x00000000)`. These specific registry values being set to 0 have essentially no legitimate administrative use — they are a direct configuration of Windows share suppression. A detection rule on Sysmon EID 13 targeting either value name under the LanmanServer Parameters key is highly specific.

**`reg.exe` with LanmanServer Parameters path in command line:** Security EID 4688 and Sysmon EID 1 both capture `reg add` or `reg set` operations targeting `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters` with `/v AutoShareServer` or `/v AutoShareWks`. Command-line monitoring for `reg.exe` operations on this specific key path is a reliable detection anchor.

**`cmd.exe` chaining two `reg.exe` invocations with `&`:** The command block modifies both `AutoShareServer` and `AutoShareWks` in a single `cmd.exe` call. The use of `&` to chain multiple `reg.exe` calls targeting the same key path in a single session is characteristic of scripted configuration changes rather than interactive administration.

**Registry delete of the same values (cleanup visibility):** Sysmon EID 12 records the `DeleteValue` operations for both keys. If you observe EID 12 `DeleteValue` on `AutoShareServer` or `AutoShareWks` after an EID 13 `SetValue` on the same paths, this lifecycle — set then delete — is itself a behavioral signature of a test or cleanup operation.
