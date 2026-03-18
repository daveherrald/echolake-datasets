# T1486-9: Data Encrypted for Impact — Data encrypt using DiskCryptor

## Technique Context

T1486 (Data Encrypted for Impact) encompasses adversary use of full-disk and volume encryption to deny access to systems and data for extortion or disruption. DiskCryptor is a legitimate open-source disk encryption utility that has been repurposed by ransomware operators, most notably the group behind RagnarLocker ransomware, which deployed DiskCryptor as its encryption engine. Rather than encrypting individual files like most ransomware, DiskCryptor encrypts entire volumes at the block level, rendering the file system inaccessible. This bypasses file-level AV scanning and makes individual-file recovery impossible without the encryption key.

Test T1486-9 launches DiskCryptor's binary from its default installation path: `cmd.exe /c "%PROGRAMFILES%\dcrypt\dcrypt.exe"`. The test depends on DiskCryptor being pre-installed as a prerequisite. In the defended variant, `dcrypt.exe` was not present (or was immediately blocked), and `cmd.exe` exited with `0x1`. The same outcome occurred in this undefended run — DiskCryptor was not installed as a prerequisite on this test execution, so the actual encryption behavior is absent from both datasets.

## What This Dataset Contains

This is a compact dataset (4-second window, 22:36:59–22:37:03 UTC) capturing the invocation attempt.

**Security EID 4688** records the essential evidence. PowerShell (running as `NT AUTHORITY\SYSTEM`) spawns `cmd.exe` with:

```
"cmd.exe" /c ""%PROGRAMFILES%\dcrypt"\dcrypt.exe"
```

This single event establishes the intent: a programmatic attempt to launch `dcrypt.exe` from the Program Files path, initiated by a SYSTEM-context PowerShell process. The `cmd.exe` process exits with `0x1`, indicating the command failed — `dcrypt.exe` was not found at the expected path.

Two `whoami.exe` test framework events are present.

**Sysmon EID 1** captures `cmd.exe` spawned by PowerShell and `whoami.exe`. No `dcrypt.exe` process creation appears in either Security or Sysmon — the binary was absent.

**Sysmon EID 3** (NetworkConnect): `MsMpEng.exe` (Windows Defender, even though disabled for real-time protection, may still perform cloud lookups) made a connection to `48.211.72.139:443`. This is Defender's telemetry or cloud lookup infrastructure — background activity from the Defender service, not related to the technique. This same IP appears in T1490-2's dataset, confirming it is a persistent Defender background connection.

**Sysmon EID 7** (ImageLoad): 9 image load events document the PowerShell and .NET assembly stack, including `urlmon.dll` loading into PowerShell. The `urlmon.dll` load here is notable — it may reflect the ART test framework performing an HTTP check or download as part of the test infrastructure, though no corresponding Sysmon EID 3 network event from PowerShell is captured.

**Sysmon EID 11** records the PowerShell profile write.

**Sysmon EID 17** captures the PowerShell named pipe.

The PowerShell channel (107 events: 104 EID 4104 + 3 EID 4103) is test framework boilerplate only.

**Compared to the defended variant** (16 Sysmon / 12 Security / 26 PowerShell): The undefended run has slightly more Sysmon events (20 vs. 16) and fewer Security events (4 vs. 12). Since DiskCryptor was not installed in either run, the core technique behavior is absent from both. The Security count difference (12 vs. 4) in the defended run suggests Defender generated additional process inspection events even for a binary-not-found failure. The fundamental dataset quality limitation is the same in both: no `dcrypt.exe` process, no volume encryption activity.

## What This Dataset Does Not Contain

`dcrypt.exe` does not appear as a process creation in any channel. There are no DiskCryptor-specific artifacts: no `dcrypt.sys` kernel driver load event (Sysmon EID 6), no service registration for the DiskCryptor kernel driver, no volume handle acquisition, and no block-level write activity. The DiskCryptor driver installs a Windows kernel filter driver that intercepts disk I/O — its installation would generate Sysmon EID 6 (DriverLoad) events, none of which are present. Without the prerequisite installation, this dataset cannot support any behavioral detection based on DiskCryptor's encryption mechanics.

## Assessment

This dataset captures the invocation attempt for DiskCryptor rather than an active encryption operation. Its value is limited to the single Security EID 4688 event showing `dcrypt.exe` being invoked from `%PROGRAMFILES%\dcrypt\dcrypt.exe` via `cmd.exe` from a SYSTEM-context PowerShell process. This command line is sufficient to detect DiskCryptor launch attempts in environments where the binary might be present. The absence of `dcrypt.exe` in subsequent events, combined with the non-zero `cmd.exe` exit code, clearly marks this as a failed launch.

Detection engineers should treat this as pre-installation attempt telemetry. The Sysmon EID 3 network connection from `MsMpEng.exe` to `48.211.72.139:443` is Defender background activity and should not be attributed to the technique.

A dataset with DiskCryptor properly pre-installed would add: `dcrypt.exe` process creation, `dcrypt.sys` driver load (Sysmon EID 6), service installation events, volume handle opens, and potentially block-level write patterns. None of those are present here.

## Detection Opportunities Present in This Data

- **Security EID 4688**: `dcrypt.exe` launch from `%PROGRAMFILES%\dcrypt\` via `cmd.exe` from a PowerShell SYSTEM process. The path `C:\Program Files\dcrypt\dcrypt.exe` is specific enough to be a high-confidence IOC — DiskCryptor has no legitimate enterprise use case on standard workstations.
- **Sysmon EID 1**: `cmd.exe` spawned by `powershell.exe` with `dcrypt.exe` in the command line. The `%PROGRAMFILES%\dcrypt` path expansion in the command line is observable even before `dcrypt.exe` is found.
- **Presence of `dcrypt.exe`**: If DiskCryptor is installed (as a prerequisite or by an attacker), its presence in `Program Files` is itself anomalous. File creation events (Sysmon EID 11) or installer execution events for DiskCryptor would precede this launch attempt in an actual attack.
- **Sysmon EID 6** (not present here, but expected with DiskCryptor installed): `dcrypt.sys` kernel driver load is the highest-fidelity behavioral indicator for DiskCryptor activity and would appear before any volume encryption.
