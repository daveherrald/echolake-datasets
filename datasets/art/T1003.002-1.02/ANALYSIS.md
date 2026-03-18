# T1003.002-1: Security Account Manager — Registry dump of SAM, creds, and secrets

## Technique Context

The Security Account Manager (SAM) database stores local user account credentials as NTLM hashes. Extracting the SAM allows an attacker to perform offline password cracking or pass-the-hash attacks against local accounts, enabling lateral movement to other systems that share the same local administrator password — a common finding in environments where local admin accounts are not randomized (e.g., pre-LAPS deployments).

The SAM registry hive is locked while Windows is running, but the Win32 `RegSaveKey` API (invoked via `reg.exe save`) can create an exportable copy while bypassing the file lock. A complete credential extraction requires three hive dumps: `HKLM\SAM` (the account database), `HKLM\SYSTEM` (the boot key needed to decrypt SAM), and `HKLM\SECURITY` (cached domain credentials and LSA secrets). Together these files contain everything needed to decrypt all local credentials offline using tools like secretsdump.py or Mimikatz.

Detection focuses on `reg.exe` being invoked with `save HKLM\SAM`, `save HKLM\SYSTEM`, or `save HKLM\SECURITY` arguments; file creation events for the resulting hive files in temp or unusual directories; and registry access audit events for `HKLM\SAM`. This technique requires administrative privileges but does not require touching LSASS memory, making it distinct from T1003.001.

## What This Dataset Contains

This dataset was collected from ACME-WS06 (Windows 11 Enterprise Evaluation, `acme.local` domain) with Windows Defender disabled. Execution was as `NT AUTHORITY\SYSTEM`.

**Security channel (14 events: 7x EID 5379, 7x EID 4688):** The 7 EID 4688 process creation events show the full execution chain. `powershell.exe` spawns `whoami.exe` (pre-check), then `cmd.exe` which in turn invokes `reg.exe` three times (PIDs 0x778, 0xae8, 0x1758 — the SAM, SYSTEM, and SECURITY hive saves), then `whoami.exe` again (post-check), then `cmd.exe` for cleanup. The three sequential `reg.exe` creations are the core attack artifact visible in the Security log.

**Sysmon channel (40 events: 22x EID 11, 7x EID 1, 6x EID 7, 4x EID 10, 1x EID 17):** The EID 1 process creation events provide full command line detail. The `reg.exe` cleanup command reveals the dump paths: `"cmd.exe" /c del %%temp%%\sam >nul 2> nul & del %%temp%%\system >nul 2> nul & del %%temp%%\security >nul 2> nul`. This confirms the three dump files were created at `%TEMP%\sam`, `%TEMP%\system`, and `%TEMP%\security`. Sysmon EID 11 captures the `reg.exe` (PID 5976) creating `C:\Windows\Temp\security` at 22:44:56 UTC — a direct file creation artifact from the SECURITY hive save. EID 10 events show `powershell.exe` opening `whoami.exe` and `cmd.exe` with `0x1FFFFF` access (standard ART test framework child process spawning pattern).

**PowerShell channel (93 events, all EID 4104):** The Invoke-AtomicTest framework blocks are present including `Import-Module 'C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1' -Force` and the cleanup invocation `Invoke-AtomicTest T1003.002 -TestNumbers 1 -Cleanup -Confirm:$false`.

**Compared to the defended dataset (sysmon: 39, security: 16, powershell: 43):** Event counts are comparable — the defended run had slightly more Sysmon events (39 vs. 40) but fewer security events (16 vs. 14 undefended). The key difference is in what Sysmon EID 11 captured: the defended run likely did not record hive dump file creation because Defender blocked the `reg.exe` calls before they could complete. Here, the actual `C:\Windows\Temp\security` file creation is visible. The cleanup command in Sysmon EID 1 (`del %%temp%%\sam... system... security`) confirms all three hive files were created successfully.

## What This Dataset Does Not Contain

The dataset does not include registry access audit events (EID 4656 or EID 4663) for the SAM hive — these require enabling "Object Access" subcategory auditing at a more granular level than the test environment's default policy. There are no network events (the hives were dumped locally, not exfiltrated during the test window). The actual hive file content is not present — this dataset captures the telemetry, not the credential material itself. The `reg.exe` command lines in the Security EID 4688 events are truncated in the sample, but the cleanup command in Sysmon EID 1 provides the dump file paths unambiguously.

## Assessment

This is a clean, well-documented SAM hive dump dataset. The combination of three sequential `reg.exe` process creation events in Security EID 4688, the `C:\Windows\Temp\security` file creation in Sysmon EID 11, and the cleanup command in Sysmon EID 1 together provide multiple corroborating detection opportunities. The fact that event counts are similar to the defended version suggests this technique may have partially executed even under defense — but the file creation artifacts confirming successful dumps only appear here. Useful for testing detection logic against the complete registry save sequence.

## Detection Opportunities Present in This Data

1. **EID 4688 / Sysmon EID 1 — three sequential `reg.exe` invocations:** Seeing `reg.exe` spawned three times in rapid succession from the same parent, particularly with `save HKLM\SAM`, `save HKLM\SYSTEM`, or `save HKLM\SECURITY` in the command line, is a high-fidelity indicator of credential harvesting.

2. **Sysmon EID 11 — hive file creation in temp directories:** `reg.exe` creating files named `sam`, `system`, or `security` (without extensions) in `C:\Windows\Temp\` or `%TEMP%` is a direct artifact. The filename pattern is distinctive and rarely occurs legitimately.

3. **EID 4688 — cleanup command pattern:** `cmd.exe /c del %temp%\sam ... del %temp%\system ... del %temp%\security` appearing after an `reg.exe` execution cluster confirms successful dump creation and is itself a detection opportunity even if the initial `reg.exe` events were missed.

4. **Sysmon EID 10 — `reg.exe` accessing `lsass.exe` or SAM handles:** While this test uses `reg.exe save` rather than direct LSASS access, correlating `reg.exe` EID 10 events with subsequent SAM-related file creation provides a behavioral chain for detection.

5. **EID 5379 — credential manager read operations:** The seven EID 5379 events from SYSTEM coinciding with this activity represent credential enumeration that could be correlated with the reg.exe activity to flag the full credential access episode.

6. **EID 4688 (Security) — `reg.exe` parent process anomaly:** On a typical domain workstation, `reg.exe` being invoked by `cmd.exe` which was itself spawned by `powershell.exe` running as SYSTEM is an unusual process lineage that warrants investigation.
