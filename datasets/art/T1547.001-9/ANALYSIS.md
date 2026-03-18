# T1547.001-9: Registry Run Keys / Startup Folder — SystemBC Malware-as-a-Service Registry

## Technique Context

T1547.001 (Registry Run Keys / Startup Folder) — this test emulates the specific persistence technique used by SystemBC, a commodity malware-as-a-service proxy/backdoor widely used in ransomware operations. SystemBC registers a SOCKS5 proxy payload under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` using the value name `socks5_powershell`, with a value that invokes a hidden PowerShell window. This test replicates that exact registry write, enabling defenders to validate detections tuned to SystemBC's known persistence IOC.

## What This Dataset Contains

The dataset captures a 6-second window on ACME-WS02 during execution of the ART test that writes the SystemBC-style run key.

**Sysmon Event 13 (RegistrySetValue)** is the primary indicator, explicitly tagged by sysmon-modular:

```
RuleName: technique_id=T1547.001,technique_name=Registry Run Keys / Start Folder
TargetObject: HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Run\socks5_powershell
Details: powershell.exe -windowstyle hidden -ExecutionPolicy Bypass -File
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

Note: the key is written to `HKU\.DEFAULT` (the SYSTEM account's registry hive) rather than a named user's HKCU, because the test ran as `NT AUTHORITY\SYSTEM`. This reflects a realistic artifact of SYSTEM-context persistence attempts that target the default user hive.

**PowerShell 4104 / 4103 script block and module logging** captures the full test code:

```powershell
$RunKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
Set-ItemProperty -Path $RunKey -Name "socks5_powershell" -Value "powershell.exe -windowstyle hidden -ExecutionPolicy Bypass -File"
```

The 4103 event records `CommandInvocation(Set-ItemProperty)` with all parameters including the value name `socks5_powershell` and the full command string, providing a complete audit record.

**Sysmon Event 1 (ProcessCreate):** `powershell.exe` (tagged T1059.001) and `whoami.exe` (tagged T1033) — the inner PowerShell execution and identity check.

**Security events (4688/4689/4703):** Two process-create events plus exits and a token adjustment. All under SYSTEM context.

The sysmon-modular ProcessCreate include filter matched `powershell.exe` (T1059.001 rule), so the inner PowerShell spawn is captured in Sysmon Event 1, complementing the Security 4688 records.

## What This Dataset Does Not Contain

- **No payload execution.** The value written to the run key points to a PowerShell command that is truncated (no actual script file path follows `-File`), and no logon occurred during collection. There is no follow-on process-create for the "malware."
- **No network events.** SystemBC is a network proxy; no network telemetry is present because the payload was never executed.
- **No file creation.** The SystemBC payload file itself is not dropped — the test only writes the persistence registry key.
- **No HKLM run key.** The test targets HKCU (user-level persistence), not HKLM (machine-level). The `HKU\.DEFAULT` path reflects SYSTEM context, not a named user's HKCU hive.

## Assessment

This dataset provides a clean, high-fidelity example of a named threat actor's persistence IOC captured across three complementary log sources. The Sysmon Event 13 carries the technique name in the RuleName field, the PowerShell logs carry the full command text, and the Security log provides process lifecycle context.

The value name `socks5_powershell` and the `-windowstyle hidden -ExecutionPolicy Bypass` pattern are well-known SystemBC indicators. This dataset is particularly useful for testing string-based detections against known malware persistence patterns and for validating that Sysmon run-key monitoring rules fire on the `HKU\.DEFAULT` hive (not just `HKCU`), which can be a gap in detection coverage when rules only monitor the per-user hive path.

## Detection Opportunities Present in This Data

- **Sysmon Event 13:** Write to `*\Software\Microsoft\Windows\CurrentVersion\Run\socks5_powershell` — the value name is a known SystemBC IOC.
- **Sysmon Event 13:** Any Run key value containing `powershell.exe -windowstyle hidden -ExecutionPolicy Bypass` is suspicious regardless of the value name.
- **PowerShell 4104 / 4103:** `Set-ItemProperty` writing to a Run key path is detectable from script block content. The value `-windowstyle hidden` combined with `-ExecutionPolicy Bypass` in a Run key value is a high-confidence indicator.
- **HKU\.DEFAULT Run key:** Detections that only monitor `HKCU` mapped paths may miss persistence written to `HKU\.DEFAULT` by SYSTEM-context processes — this dataset validates coverage of that path.
- **Process chain:** `powershell.exe` under SYSTEM writing to a Run key, with no interactive parent, is anomalous.
