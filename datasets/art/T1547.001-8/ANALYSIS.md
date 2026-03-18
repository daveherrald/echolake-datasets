# T1547.001-8: Registry Run Keys / Startup Folder — Add Persistence via Recycle Bin

## Technique Context

T1547.001 (Registry Run Keys / Startup Folder) includes a lesser-known sub-variant where adversaries abuse the Windows Recycle Bin COM object registration to achieve persistence. The Recycle Bin CLSID (`{645FF040-5081-101B-9F08-00AA002F954E}`) has a shell open command handler registered in `HKCR`. By overwriting the default value of `HKCR\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}\shell\open\command\(Default)`, an attacker can cause arbitrary code to execute whenever a user opens the Recycle Bin in Explorer. This is classified under T1547.001 because it involves registry modification to achieve automatic execution tied to a user action (shell interaction), but it requires SYSTEM or administrative privileges to write to HKCR.

## What This Dataset Contains

The dataset captures a 6-second window on ACME-WS02 during execution of the ART test that modifies the Recycle Bin COM shell handler.

**Sysmon Event 13 (RegistrySetValue) is the primary indicator:**

```
TargetObject: HKCR\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}\shell\open\command\(Default)
Details: calc.exe
Image: C:\Windows\system32\reg.exe
```

**Sysmon Event 1 (ProcessCreate)** shows the execution chain:
- `whoami.exe` (tagged T1033) — ART test framework identity check
- `cmd.exe` (tagged T1083) — shell spawned to run `reg.exe`
- `reg.exe` (tagged T1083) — the registry modification tool

**Security events (4688/4689/4703):** Three process-create events for the cmd/reg chain plus process-exit pairs and a token adjustment. The 4688 events capture process names and parents under SYSTEM context.

Unlike test -7 (shortcut) and -9 (run key), this test used `reg.exe` via `cmd.exe` rather than PowerShell `Set-ItemProperty`, which is why no meaningful PowerShell 4104 content appears — the PowerShell test framework only invoked `cmd.exe` to run the reg command. The 34 PowerShell events are entirely test framework boilerplate (`Set-StrictMode`, `Set-ExecutionPolicy`, profile load).

The Sysmon rule for EventID 13 matched on the default `-` rule rather than a named T1547.001 rule, meaning the sysmon-modular config does not have a specific include rule for this CLSID path — the event was captured by a broad registry monitoring rule, not a targeted persistence detection rule.

## What This Dataset Does Not Contain

- **No execution of the payload.** The Recycle Bin was not opened during the test window, so there is no process-create event for `calc.exe` launching from the shell handler.
- **No file creation events in Startup folders.** This variant uses registry modification, not filesystem placement.
- **No object access auditing.** Registry write auditing is not enabled (audit_policy: object_access: none), so there is no Security 4657 event.
- **No Sysmon DNS or network events.** The payload is benign and the modification does not trigger network activity.
- **No T1547.001-tagged Sysmon 13.** The sysmon-modular config did not fire a named T1547.001 rule for this HKCR path — detection relies on the broad registry monitoring catch-all.

## Assessment

The dataset successfully captures the registry modification that constitutes this persistence technique. The key forensic evidence is the Sysmon 13 event showing `reg.exe` writing `calc.exe` to the Recycle Bin shell open command handler. Windows Defender did not block this operation.

The execution path (PowerShell test framework spawning `cmd.exe` spawning `reg.exe`) is visible across Sysmon process-create and Security 4688 events. The dataset is relatively compact and clean: while PowerShell boilerplate dominates the event count, the meaningful attack events are unambiguous.

The HKCR COM shell handler abuse path is underrepresented in many detection rule sets compared to the more commonly detected Run key paths, making this dataset useful for validating coverage of this specific persistence location.

## Detection Opportunities Present in This Data

- **Sysmon Event 13:** Writes to `HKCR\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}\shell\open\command\` — the Recycle Bin shell open handler — by any process other than legitimate installers is anomalous and high-confidence.
- **Security 4688:** `reg.exe` spawned by `cmd.exe` spawned by `powershell.exe` under SYSTEM, with a command line containing the Recycle Bin CLSID, is detectable via command-line logging.
- **Process chain:** `powershell.exe` → `cmd.exe` → `reg.exe` is a common pattern for scripted registry manipulation and is worth baselining.
- **HKCR shell command handler writes:** Any modification to `HKCR\CLSID\*\shell\*\command\` values by non-installer processes warrants investigation, regardless of which CLSID is targeted.
