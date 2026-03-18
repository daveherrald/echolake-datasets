# T1546.011-3: Application Shimming — Registry Key Creation and/or Modification Events for SDB

## Technique Context

T1546.011 (Application Shimming) abuses the Windows Application Compatibility Framework. Beyond dropping `.sdb` files to disk, a complete shim installation registers the database in two registry locations: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom\<exe>` (per-application shim reference) and `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB\<GUID>` (global registry of installed shim databases). Attackers target these keys because the OS consults them at process load time, making them a reliable persistence mechanism. Defenders focus on write access to these keys — especially writes by non-installer processes — and on correlating registry entries with `.sdb` files in unexpected locations.

## What This Dataset Contains

This test installs a shim database via the `sdbinst.exe` equivalent path, resulting in both registry writes and (indirectly) confirming the shim database was placed. The strongest evidence is in Sysmon Event ID 13 (Registry Value Set), which fires twice with `RuleName: technique_id=T1546.011,technique_name=Application Shimming`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom\AtomicRedTeamT1546.011` — value `AtomicRedTeamT1546.011`
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB\AtomicRedTeamT1546.011` — value `AtomicRedTeamT1546.011`

Both are written by `powershell.exe` running as `NT AUTHORITY\SYSTEM`.

Sysmon Event ID 1 shows child process creation of `powershell.exe` (tagged `T1059.001`) as the execution vehicle, and `whoami.exe` (tagged `T1033`) as the usual post-execution confirmation. The Security channel (4688) reproduces the test framework command line. Three Sysmon Event ID 3 records show Windows Defender (`MsMpEng.exe`) initiating outbound TCP connections shortly after the test, consistent with signature update activity and not related to the attack.

The PowerShell channel (4104) captures the script block text for the `New-ItemProperty` or equivalent calls that write the registry keys.

## What This Dataset Does Not Contain

- **No `.sdb` file creation event**: this test writes only the registry entries; it does not drop a new shim database file to `apppatch\Custom\`. A combined dataset pairing with T1546.011-2 would be needed to cover the full installation chain.
- **No `sdbinst.exe`**: the registry writes are performed directly from PowerShell using `New-ItemProperty`, which is one method attackers use to avoid the `sdbinst.exe` process creation artifact. Detection rules that key on `sdbinst.exe` will miss this variant.
- **Sysmon ProcessCreate filtering**: the outer test framework PowerShell is not captured by Sysmon Event ID 1. Only the child PowerShell that matches the `T1059.001` include rule appears.
- The PowerShell channel is overwhelmingly test framework boilerplate (`Set-StrictMode`, `Set-ExecutionPolicy -Scope Process -Bypass`, `$_.PSMessageDetails`, `$_.OriginInfo`). The substantive script block containing the registry writes appears but is surrounded by noise.

## Assessment

The two Sysmon 13 events with accurate T1546.011 rule tags are the core detection value here. This dataset is well-suited for validating registry-write detections on the `AppCompatFlags` key tree. The PowerShell-direct method of writing the keys (rather than via `sdbinst.exe`) makes this dataset representative of a more sophisticated evasion variant. Pairing this dataset with T1546.011-2 gives you both the file-creation and registry-write phases of a complete shim installation. Adding Sysmon registry create (Event ID 12) in addition to value set (Event ID 13) would also be useful to capture key creation events when the registry key itself is new.

## Detection Opportunities Present in This Data

1. **Sysmon Event ID 13 — writes to `AppCompatFlags\Custom\`**: Alert on `SetValue` events targeting `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom\*` from any process other than a known software installer.
2. **Sysmon Event ID 13 — writes to `AppCompatFlags\InstalledSDB\`**: The `InstalledSDB` key is written when a shim database is registered. Writes here from PowerShell or from any non-`sdbinst.exe` process are high-confidence signals.
3. **PowerShell Event ID 4104 — script block using `New-ItemProperty` against AppCompatFlags**: Detect PowerShell accessing the `AppCompatFlags` registry path via cmdlets.
4. **Security Event ID 4688 — PowerShell writing AppCompatFlags registry without preceding sdbinst.exe**: A process chain involving PowerShell and AppCompatFlags manipulation with no `sdbinst.exe` parent is anomalous.
5. **Correlation of file creation (T1546.011-2) and registry write (this dataset)**: A shim database file appearing in `apppatch\Custom\` within a short time window of `AppCompatFlags` registry writes is a high-fidelity combined indicator.
