# T1546.002-1: Screensaver — Set Arbitrary Binary as Screensaver

## Technique Context

T1546.002 (Screensaver) exploits the Windows screensaver mechanism for persistence. The screensaver is configured through several registry values under `HKCU\Control Panel\Desktop`: `SCRNSAVE.EXE` specifies the screensaver binary path, `ScreenSaveActive` enables it, and `ScreenSaveTimeout` controls inactivity delay. Because the screensaver is launched by the Windows desktop process at the user level, an attacker can point `SCRNSAVE.EXE` to any executable and it will run in the user's context after the timeout without requiring additional privilege. This technique is particularly effective in environments where users leave workstations unattended, and it survives reboots since the registry values persist. Detection teams focus on writes to `SCRNSAVE.EXE` pointing to paths outside `C:\Windows\System32`.

## What This Dataset Contains

The dataset covers 6 seconds (2026-03-13 23:37:50–23:37:56) on ACME-WS02 running as NT AUTHORITY\SYSTEM.

**Sysmon (45 events, IDs: 1, 7, 10, 11, 17):** This is the richest sysmon dataset in the T1546 screensaver test. Five Sysmon ID=1 (ProcessCreate) events capture the technique's execution chain directly. After the test framework `whoami.exe` check, `cmd.exe` launches with:

```
"cmd.exe" /c reg export "HKEY_CURRENT_USER\Control Panel\Desktop" C:\Windows\system32\config\systemprofile\AppData\...
```

This is followed by four sequential `reg.exe` invocations that configure the screensaver persistence:

```
reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /v ScreenSaveActive /t REG_SZ /d 1
reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /v ScreenSaveTimeout /t REG_SZ /d 60
reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /v ScreenSaverIsSecure /t REG_SZ /d 0
reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /v SCRNSAVE.EXE /t REG_SZ /d <payload_path>
```

Sysmon ID=11 (FileCreate) events show `reg.exe` writing temporary registry export files, confirming the backup step executed. The remaining Sysmon events are PowerShell DLL loads (ID=7) and process access events (ID=10) from the test framework.

**Security (20 events, IDs: 4688, 4689, 4703):** Security channel 4688 events duplicate the `cmd.exe` and `reg.exe` command lines, providing independent confirmation of all four registry modifications with their exact value data.

**PowerShell (42 events, IDs: 4103, 4104):** The PowerShell channel contains only ART test framework boilerplate (`Set-StrictMode`, `Set-ExecutionPolicy Bypass`). No technique-specific PowerShell content is present.

## What This Dataset Does Not Contain

- **No Sysmon ID=13 (RegistryValueSet):** The sysmon-modular configuration does not include a rule matching `HKCU\Control Panel\Desktop\SCRNSAVE.EXE` or adjacent keys. All registry modification evidence comes exclusively from `reg.exe` command-line arguments.
- **No screensaver execution:** The test sets the registry values but does not wait for or trigger the screensaver timeout, so there is no `scrnsave.exe` (or equivalent payload) process creation.
- **No object access auditing:** Registry write audit events (4657) are not generated due to `object_access: none` policy.
- **The SCRNSAVE.EXE value payload path is truncated** in the available Sysmon output, though it is recoverable from the Security 4688 command line for the corresponding `reg.exe` invocation.

## Assessment

This dataset provides well-structured, multi-step evidence of screensaver persistence configuration. The four sequential `reg.exe` calls targeting `HKEY_CURRENT_USER\Control Panel\Desktop` are clearly visible in both Sysmon ID=1 and Security ID=4688. The `SCRNSAVE.EXE` write is the highest-value indicator. The dataset would be meaningfully strengthened by adding Sysmon ID=13 rules for `HKCU\Control Panel\Desktop` to capture the registry value set events directly, and by including a screensaver trigger phase to show downstream execution. As-is, it supports command-line–based detections reliably.

## Detection Opportunities Present in This Data

1. **Sysmon ID=1 / Security ID=4688:** `reg.exe` writing to `HKEY_CURRENT_USER\Control Panel\Desktop\SCRNSAVE.EXE` with a value pointing outside `C:\Windows\System32` is a high-fidelity indicator.
2. **Sysmon ID=1 / Security ID=4688:** `reg.exe` writing `ScreenSaveActive=1` and `ScreenSaveTimeout` to a low value (e.g., ≤60 seconds) in the same session suggests deliberate screensaver weaponization.
3. **Sysmon ID=1:** The process chain PowerShell → cmd.exe → multiple sequential `reg.exe` calls targeting `HKCU\Control Panel\Desktop` is anomalous on a managed workstation.
4. **Security ID=4688:** `reg.exe` invocations for `HKCU\Control Panel\Desktop` screensaver values executing under NT AUTHORITY\SYSTEM (or any non-interactive user context) is suspicious.
5. **Composite detection:** The combination of `ScreenSaveActive=1`, `ScreenSaveTimeout=<low_value>`, and `SCRNSAVE.EXE=<non-system32_path>` written in the same time window, even across separate `reg.exe` calls, is a strong behavioral cluster.
