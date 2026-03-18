# T1003.003-2: NTDS — Copy NTDS.dit from Volume Shadow Copy

## Technique Context

T1003.003 (NTDS) involves extracting the Active Directory database file (`ntds.dit`) to obtain credential hashes for all domain users. The NTDS.dit file contains NTLM hashes, Kerberos keys, and plaintext reversibly encrypted passwords for every account in the domain — making it the highest-value single credential artifact an attacker can obtain. The file is always locked while the domain controller is running, but Volume Shadow Copies provide a point-in-time snapshot through which locked files can be accessed.

This specific test copies NTDS.dit from a VSC path (`\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy[N]\Windows\NTDS\NTDS.dit`) along with the SYSTEM registry hive needed to decrypt it. The copy is performed via `cmd.exe` with direct file copy commands. This is a simple, effective approach that requires only `cmd.exe` and an existing shadow copy — no specialized tools needed. The SYSTEM hive is also saved via `reg.exe save HKLM\SYSTEM` to provide the boot key for offline decryption.

An important note: this test runs on a domain **workstation** (ACME-WS06), not a domain controller. The workstation's own VSC may not contain NTDS.dit unless the workstation has been used for AD backup operations. The test will attempt the copy but succeed only if the shadow copy path resolves to an existing file. Detection focus is on the VSC path access pattern and the `reg.exe save HKLM\SYSTEM` command, both of which are high-confidence indicators regardless of whether NTDS.dit is actually present.

## What This Dataset Contains

This dataset was collected from ACME-WS06 (Windows 11 Enterprise Evaluation, `acme.local` domain) with Windows Defender disabled. Execution was as `NT AUTHORITY\SYSTEM`.

**Sysmon channel (28 events: 12x EID 11, 7x EID 7, 5x EID 1, 4x EID 10, 1x EID 17):** The EID 1 process creation events reveal the complete execution chain. At 22:46:20 UTC, `cmd.exe` (PID 1716) is spawned with the command `"cmd.exe" /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\Windows\Temp\ntds.dit & copy \\?\GLOBALROOT\Device\HarddiskVolume...`. This is the NTDS.dit copy command — the full command string is truncated in the sample but the VSC path and destination `C:\Windows\Temp\ntds.dit` are visible. At the same timestamp, `reg.exe` (PID 5236) runs with `reg save HKLM\SYSTEM C:\Windows\Temp\SYSTEM_HIVE`, captured in Sysmon EID 1. Sysmon EID 11 confirms `reg.exe` creating `C:\Windows\Temp\SYSTEM_HIVE` at 22:46:20 UTC — the SYSTEM hive dump file is visible as a direct file creation artifact.

**Security channel (5 events, all EID 4688):** Five process creation events: `powershell.exe` spawning `whoami.exe` (0xc30, pre-check), `cmd.exe` (0x6b4, the VSC copy), `reg.exe` (0x1474, SYSTEM hive save), `whoami.exe` (0xec8, post-check), and `cmd.exe` (0x16e0, cleanup).

**PowerShell channel (104 events: 102x EID 4104, 2x EID 4103):** The ART test framework events including the standard Import-Module and runtime stubs.

**Compared to the defended dataset (sysmon: 15, security: 9, powershell: 41):** The undefended run produced nearly double the Sysmon events (28 vs. 15) and fewer Security events (5 vs. 9). Most critically, the Sysmon EID 1 events showing the VSC copy command and the `reg save HKLM\SYSTEM` command are present here but would have been blocked (or partially blocked) in the defended run. The EID 11 file creation for `C:\Windows\Temp\SYSTEM_HIVE` confirms the SYSTEM hive was successfully written — an artifact absent from the defended dataset.

## What This Dataset Does Not Contain

VSS snapshot creation events are absent — this test assumes an existing shadow copy is available (HarddiskVolumeShadowCopy1). If no shadow copy existed, the copy command would fail silently. The outcome of the NTDS.dit copy itself (whether it succeeded or failed due to the file not existing on the workstation's VSC) is not directly visible in the telemetry — but the command execution itself is confirmed. The dataset does not include Active Directory replication events or LSASS access patterns associated with DCSync. There are no network events or lateral movement artifacts.

## Assessment

This is one of the cleaner datasets in the T1003.003 series for demonstrating the VSC copy technique. The Sysmon EID 1 command line showing `copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\Windows\Temp\ntds.dit` is an unambiguous detection artifact. The concurrent `reg save HKLM\SYSTEM` command — visible in both Sysmon EID 1 and confirmed by EID 11 file creation — shows the attacker collecting the decryption material alongside the database. This pairing (NTDS copy + SYSTEM hive save) is a signature behavior of complete domain credential extraction preparation.

## Detection Opportunities Present in This Data

1. **Sysmon EID 1 — VSC path in copy command:** `cmd.exe` executing a `copy` command with `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy` as the source path is a high-fidelity indicator. The destination path `C:\Windows\Temp\ntds.dit` or any `ntds.dit` copy outside the AD database directory is an immediate alert trigger.

2. **Sysmon EID 1 — `reg save HKLM\SYSTEM` command:** `reg.exe` invoked with `save HKLM\SYSTEM` to a temp directory, especially when appearing in the same execution chain as a NTDS.dit copy, indicates the attacker is collecting both pieces needed for offline decryption.

3. **Sysmon EID 11 — SYSTEM_HIVE file creation by reg.exe:** The file `C:\Windows\Temp\SYSTEM_HIVE` created by `reg.exe` is a direct artifact. Any registry hive dump file (lacking a `.hiv` extension) in a temp directory is suspicious.

4. **EID 4688 — concurrent reg.exe and cmd.exe from the same parent:** Three process creation events in rapid succession from the same parent (powershell.exe) — cmd.exe for the VSC copy, reg.exe for the SYSTEM hive — within a few seconds of each other indicates coordinated credential material collection.

5. **Sysmon EID 10 — powershell.exe accessing cmd.exe with full access:** The EID 10 events showing `powershell.exe` opening `cmd.exe` and subsequent child processes with `0x1FFFFF` provide a behavioral chain from the parent PowerShell session to the actual copy commands.

6. **EID 4688 — reg.exe parent process anomaly:** `reg.exe` being spawned by `cmd.exe` which was itself spawned by `powershell.exe` running as SYSTEM, without any interactive user context, is an unusual process lineage on a domain workstation not running administrative automation.
