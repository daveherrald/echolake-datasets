# T1546-9: Event Triggered Execution — Persistence using STARTUP-PATH in MS-WORD

## Technique Context

T1546 (Event Triggered Execution) covers a broad class of persistence mechanisms where an attacker registers code to execute automatically in response to a system or user event. This sub-technique targets Microsoft Word's `STARTUP-PATH` registry value under `HKCU\Software\Microsoft\Office\16.0\Word\Options`. When Word launches, it loads files from the configured startup path. By pointing this path to an attacker-controlled directory, any document or template placed there executes automatically when a user opens Word — no user interaction beyond launching the application is required. This is a lower-profile persistence mechanism than run keys or scheduled tasks, and it is user-scoped, meaning it requires only HKCU write access and does not need elevation. Detection teams often focus on the `STARTUP-PATH` registry value modification as the primary indicator.

## What This Dataset Contains

The dataset captures a short execution chain (6 seconds, 2026-03-13 23:37:18–23:37:24) on ACME-WS02 running as NT AUTHORITY\SYSTEM via QEMU guest agent.

**Sysmon (31 events, IDs: 1, 7, 10, 11, 17):** The core technique evidence is in two Sysmon ID=1 (ProcessCreate) events. First, `cmd.exe` launches with the command:

```
"cmd.exe" /c reg add "HKCU\Software\Microsoft\Office\16.0\Word\Options" /v STARTUP-PATH /t REG_SZ /d "C:\Users\ACME-WS02$\AppData\Roaming\Microsoft\Windows\Recent" /f
```

This is immediately followed by `reg.exe` executing the same registry add directly. Both carry the rule tag `technique_id=T1012,technique_name=Query Registry` from sysmon-modular. A `whoami.exe` process creation (tagged T1033) precedes the registry write, consistent with the ART test framework confirming execution context. Multiple Sysmon ID=7 (ImageLoad) events show PowerShell loading DLLs tagged as T1055 and T1059.001 patterns — this is the test framework infrastructure, not the technique itself. Sysmon ID=17 (PipeCreate) shows the PowerShell hosting pipe `\PSHost.*`, also test framework infrastructure.

**Security (12 events, IDs: 4688, 4689, 4703):** Process creation (4688) and termination (4689) events for `cmd.exe` and `reg.exe` are present, providing command-line confirmation of the registry write via the Security channel. A single 4703 (token right adjusted) event is present, related to SYSTEM context.

**PowerShell (34 events, IDs: 4103, 4104):** The PowerShell channel contains only ART test framework boilerplate: repeated `Set-StrictMode -Version 1` fragments (ID=4104) and `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass` (ID=4103). No technique-specific PowerShell script blocks are present.

## What This Dataset Does Not Contain

- **No Sysmon ID=13 (RegistryValueSet):** The sysmon-modular configuration does not include a registry value set rule matching `HKCU\Software\Microsoft\Office\*\Word\Options\STARTUP-PATH`, so the actual registry write is not captured as a Sysmon event. The write is only visible via `reg.exe` command-line arguments in ID=1 and 4688 events.
- **No file system writes to the startup path:** The test only sets the registry value; it does not drop a malicious document into the path.
- **No Word process launch:** There is no evidence of `winword.exe` executing or loading from the startup path, because the test only configures persistence rather than triggering it.
- **No object access auditing:** With `object_access: none` in the audit policy, no registry key access events (4663) are generated.

## Assessment

This dataset provides clean, minimal evidence of the registry-based configuration step of this persistence technique. The command-line arguments in both Sysmon ID=1 and Security ID=4688 are unambiguous and directly attribute the `STARTUP-PATH` modification. However, the dataset is limited to the setup phase only — there is no trigger event, no payload, and no downstream execution. For detection engineering, the command-line evidence is sufficient to build a detection on `reg.exe` or `cmd.exe` writing to `HKCU\Software\Microsoft\Office\*\Word\Options\STARTUP-PATH`. Adding Sysmon ID=13 coverage for this registry path would significantly strengthen the dataset.

## Detection Opportunities Present in This Data

1. **Security ID=4688 / Sysmon ID=1:** `reg.exe` or `cmd.exe` with command-line arguments writing to `HKCU\Software\Microsoft\Office\*\Word\Options` and value name `STARTUP-PATH` — high-fidelity, low-volume indicator.
2. **Sysmon ID=1 parent-child chain:** PowerShell spawning `cmd.exe` spawning `reg.exe` with a registry add targeting Office paths is an unusual process ancestry worth alerting on.
3. **Security ID=4688:** `reg.exe` with `/v STARTUP-PATH` in the command line, regardless of the key path, is an uncommon operation on a workstation.
4. **Sysmon ID=1 (whoami):** `whoami.exe` spawned from PowerShell under SYSTEM context immediately before a registry write is a composite indicator of scripted, privileged execution.
