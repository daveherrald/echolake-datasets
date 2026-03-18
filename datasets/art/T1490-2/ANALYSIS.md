# T1490-2: Inhibit System Recovery — Delete Volume Shadow Copies via WMI

## Technique Context

MITRE ATT&CK T1490 (Inhibit System Recovery) covers adversary actions that prevent the operating system from being restored after an attack. Deleting Volume Shadow Copies (VSCs) is the single most well-documented ransomware pre-encryption step — it removes the on-disk snapshot history that Windows and third-party backup tools rely on for point-in-time recovery. The WMI variant (`wmic.exe shadowcopy delete`) has appeared in ransomware families including Ryuk, Conti, LockBit, and BlackCat. Detection engineering teams treat VSC deletion as a high-confidence ransomware indicator because legitimate administrative activity almost never touches shadow copies in this way.

## What This Dataset Contains

The core action is captured cleanly across two sources.

**Sysmon (Event ID 1) — ProcessCreate:**
The attack chain runs as `NT AUTHORITY\SYSTEM` from `C:\Windows\TEMP\`. The test framework launches `cmd.exe /c wmic.exe shadowcopy delete`, which in turn spawns `wmic.exe shadowcopy delete` as a child. Both processes are captured with full command lines, parent/child relationships, and SHA1/MD5/SHA256/IMPHASH hashes. Sysmon applies the rule `technique_id=T1490,technique_name=Inhibit System Recovery` to both the `cmd.exe` and `wmic.exe` process create events.

**Security (Event ID 4688) — Process Creation:**
Confirms the same process chain: `whoami.exe` → `cmd.exe` → `wmic.exe`. Command-line auditing is enabled, so the full argument strings are present. The creator subject in all cases is `S-1-5-18` (SYSTEM) with logon ID `0x3E7`.

**Security (Event ID 4689) — Process Exit:**
`wmic.exe` exits with status `0x0` (success). This is significant: it means WMI accepted the deletion request. The shadow copy deletion completed.

**PowerShell channel:** Contains only test framework boilerplate — `Set-StrictMode` and `Set-ExecutionPolicy -Bypass` fragments. No WMI delete commands appear here because the test drove `wmic.exe` as a subprocess of `cmd.exe`, not through the PowerShell WMI interface.

## What This Dataset Does Not Contain

- **No WMI activity channel events.** The `Microsoft-Windows-WMI-Activity/Operational` channel is not included in this dataset's bundled files, even though the provenance shows a WMI event was observed in the source. The bundled dataset omits it; detection engineers wanting WMI provider telemetry should supplement with that channel.
- **No VSS provider or application log entries.** There is no Windows Application event confirming which shadow copies existed before deletion or how many were removed.
- **No VSS writer or backup catalog side effects.** The VSC deletion via WMI does not write to the Windows Backup Application log in the same way `wbadmin` does.
- **No Sysmon Event ID 17 named pipe** for the WMI provider process itself — `WmiPrvSE.exe` is not captured by Sysmon's include-mode ProcessCreate filter in this test.

## Assessment

This is a strong, clean dataset for the wmic VSC deletion detection use case. Both the `cmd.exe` wrapper and the `wmic.exe` payload are captured with full command lines in two independent sources (Sysmon EID 1 and Security EID 4688). The successful exit code (`0x0`) confirms the deletion completed, making this representative of real-world ransomware execution rather than a blocked attempt. The absence of the WMI activity channel is a gap worth noting for defenders who build detections around WMI provider events. To strengthen the dataset, including `Microsoft-Windows-WMI-Activity/Operational` events would provide an additional detection layer.

## Detection Opportunities Present in This Data

1. **Sysmon EID 1 — `wmic.exe` with `shadowcopy delete` arguments** spawned from `cmd.exe` under SYSTEM context; the Sysmon rule directly labels this T1490.
2. **Security EID 4688 — `wmic.exe shadowcopy delete` command line** captured via command-line auditing; no Sysmon required for this detection.
3. **Parent process chain** `cmd.exe /c wmic.exe shadowcopy delete` run from `C:\Windows\TEMP\` as SYSTEM — the temp-directory launch path is an additional anomaly indicator.
4. **Security EID 4689 exit code `0x0`** for `wmic.exe` confirms successful execution; combined with the command arguments this constitutes a high-confidence post-execution confirmation signal.
5. **`whoami.exe` as immediate predecessor** of the `cmd.exe` attack chain (from `C:\Windows\system32\`) — the test framework enumeration pattern, while not adversarial itself, provides a useful temporal anchor for correlating the attack sequence in a SIEM.
