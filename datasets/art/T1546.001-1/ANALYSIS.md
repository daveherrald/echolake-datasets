# T1546.001-1: Change Default File Association — Change Default File Association

## Technique Context

T1546.001 (Change Default File Association) abuses the Windows file association mechanism to achieve persistence or privilege escalation. When a user opens a file with a particular extension, Windows looks up the associated handler in the registry and launches the registered program. An attacker who can modify these associations — either in `HKCU\Software\Classes` (user-scoped) or `HKCR` (machine-wide) — can cause a trusted-looking file open action to instead execute an arbitrary binary. A classic example is associating `.txt` with a malicious executable or, as in this test, remapping `.hta` files so they no longer execute via `mshta.exe`. Defense teams focus on registry modifications under `HKCU\Software\Classes\*\shell\open\command` and the `assoc` / `ftype` built-in commands as primary indicators.

## What This Dataset Contains

The dataset spans 4 seconds (2026-03-13 23:37:34–23:37:38) on ACME-WS02 running as NT AUTHORITY\SYSTEM.

**Sysmon (26 events, IDs: 1, 7, 10, 11, 17):** Two Sysmon ID=1 (ProcessCreate) events carry the technique evidence. First, `whoami.exe` executes (tagged T1033). Then `cmd.exe` launches with:

```
"cmd.exe" /c assoc .hta=txtfile
```

This is tagged `technique_id=T1059.003,technique_name=Windows Command Shell` by sysmon-modular. The `assoc` built-in changes the file association for `.hta` from its default handler (HTAFile / mshta.exe) to `txtfile`, effectively defanging `.hta` execution while also setting a clear forensic marker. The process chain is: PowerShell → cmd.exe (`assoc .hta=txtfile`). The remaining Sysmon events are PowerShell infrastructure: repeated ID=7 (ImageLoad) events tagged T1055 and T1574.002, a PSHost pipe creation (ID=17), and process access events (ID=10) tagged T1055.001.

**Security (10 events, IDs: 4688, 4689, 4703):** Security channel 4688 events capture `cmd.exe` and its children (including the `assoc` invocation) with command-line arguments, providing a second copy of the technique evidence. The 4703 token adjustment event is SYSTEM context boilerplate.

**PowerShell (34 events, IDs: 4103, 4104):** The PowerShell channel contains only ART test framework boilerplate — `Set-StrictMode` fragments and `Set-ExecutionPolicy Bypass`. No technique-specific PowerShell is logged.

## What This Dataset Does Not Contain

- **No Sysmon ID=13 (RegistryValueSet):** The `assoc` command writes to `HKCU\Software\Classes\.hta` but sysmon-modular does not have a matching include rule for this registry path, so no ID=13 is generated. The write is only observable through the `assoc` command-line argument.
- **No Security ID=4657 (registry value modified):** Object access auditing is disabled (`object_access: none`), so no registry write audit events are present.
- **No ftype command:** This test uses `assoc` to change the extension-to-filetype mapping but does not modify the `ftype` (the command association for the file type itself). A complete attacker workflow would typically also change the `ftype` to point to a malicious binary.
- **No downstream execution:** The test does not open an `.hta` file to demonstrate the changed behavior, so there is no payload execution telemetry.

## Assessment

This is a compact, well-captured dataset for the configuration step of file association abuse. The `cmd.exe` command-line `assoc .hta=txtfile` in both Sysmon ID=1 and Security ID=4688 is unambiguous. For a detection engineer, this dataset is immediately usable for a command-line rule. The dataset would be strengthened by also capturing the `ftype` modification that would complete a real attack, and by including Sysmon ID=13 coverage for `HKCU\Software\Classes\*` registry writes to provide a file-association-agnostic detection.

## Detection Opportunities Present in This Data

1. **Sysmon ID=1 / Security ID=4688:** `cmd.exe` executing the `assoc` built-in with any argument that changes an extension association — particularly from a scripted or elevated context.
2. **Sysmon ID=1:** PowerShell spawning `cmd.exe` with `assoc` is an unusual parent-child relationship; interactive `assoc` changes by users do not produce this process ancestry.
3. **Security ID=4688:** `cmd.exe /c assoc` invocations run as NT AUTHORITY\SYSTEM (logon ID 0x3E7) are highly anomalous on a workstation.
4. **Sysmon ID=1 (whoami):** Scripted `whoami.exe` execution from a SYSTEM-context PowerShell process immediately before a persistence-related command is a consistent ART test-test framework pattern that also appears in real attacker tradecraft.
