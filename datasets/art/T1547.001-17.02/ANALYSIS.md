# T1547.001-17: Registry Run Keys / Startup Folder — Modify BootExecute Value

## Technique Context

T1547.001 covers persistence and privilege escalation through Windows registry run keys and startup mechanisms. The `BootExecute` value under `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager` specifies programs that run during early Windows initialization — before user-mode services start, before most driver loading completes, and before any logon occurs. The default value is `autocheck autochk *`, which runs filesystem integrity checks. An adversary who appends an entry to `BootExecute` achieves persistence that fires on every boot with essentially no endpoint security tooling active to intercept it.

This is one of the most privileged and persistent footholds available on Windows. Because execution occurs in the native API environment before the Win32 subsystem is fully initialized, many standard detection and remediation tools cannot observe or stop it during the early boot phase. Any entry in `BootExecute` must be a native executable (one that uses the native API directly), which narrows the field of realistic attack payloads but makes the persistence exceptionally durable.

This dataset was collected on ACME-WS06 (Windows 11 Enterprise Evaluation, domain `acme.local`) with Windows Defender fully disabled via Group Policy. Compare with the defended variant in `datasets/art/T1547.001-17` for the same test against an active Defender installation.

## What This Dataset Contains

The test executed as `NT AUTHORITY\SYSTEM` via QEMU guest agent. The payload first exports the current `Session Manager` key to a backup `.reg` file, then uses `Set-ItemProperty` to modify `BootExecute`, then restores the backup during cleanup.

**Sysmon (63 events — EIDs 1, 7, 10, 11, 13, 17):**

EID 1 (ProcessCreate) captures:
- `whoami.exe` (test framework identity check, tagged T1033)
- `powershell.exe` (child process, tagged T1083) with full command line: `"powershell.exe" & {if (!(Test-Path "C:\AtomicRedTeam\atomics\T1547.001\src\SessionManagerBackup.reg")) { reg.exe export "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" "C:\AtomicRedTeam\atomics\T1547.001\src\SessionManagerBackup.reg" /y }; Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "BootExecute" -Value "autocheck autoche *" -Type MultiString}` — the full modification logic including the intentionally truncated value (`autoche *` instead of `autochk *`) is captured at process creation.
- `reg.exe` (child of the inner PowerShell) for the backup export: `"C:\Windows\system32\reg.exe" export "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" C:\AtomicRedTeam\atomics\T1547.001\src\SessionManagerBackup.reg /y`

EID 13 (RegistrySetValue) produces 19 events. The sample set captures environment variable writes under `HKLM\System\CurrentControlSet\Control\Session Manager\Environment\` (e.g., `PROCESSOR_REVISION`, `TMP`, `PROCESSOR_IDENTIFIER`, `windir`, `USERNAME`) performed by `reg.exe` as part of the registry backup/restore cycle — these are side effects of the `reg.exe import` during cleanup restoring the full `Session Manager` subtree. The `BootExecute` write itself (`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute` = `Binary Data`) may be in the remaining EID 13 events in the full dataset.

EID 11 (FileCreate) shows `svchost.exe` writing `C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\State\keyValueLKG.dat` — background OS activity unrelated to the test.

EID 7 (ImageLoad) produces 25 events covering .NET runtime DLL loads for both PowerShell instances. EID 10 (ProcessAccess), EID 17 (PipeCreate) are standard test framework artifacts.

**Security (6 events — EID 4688):**

Six EID 4688 process creation events cover the full execution chain:
- Outer `powershell.exe`
- `whoami.exe` (identity check)
- Inner `powershell.exe` with the `BootExecute` modification command: `"powershell.exe" & {if (!(Test-Path "...SessionManagerBackup.reg")) { reg.exe export "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" "...SessionManagerBackup.reg" /y }; Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "BootExecute" -Value "autocheck autoche *" -Type MultiString}`
- `reg.exe` for the export: `"C:\Windows\system32\reg.exe" export "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" C:\AtomicRedTeam\atomics\T1547.001\src\SessionManagerBackup.reg /y`
- A second `powershell.exe` for cleanup (running `reg.exe import` to restore the backup)
- `reg.exe` for the import: `"C:\Windows\system32\reg.exe" import C:\AtomicRedTeam\atomics\T1547.001\src\SessionManagerBackup.reg`

All processes ran as `NT AUTHORITY\SYSTEM`.

**PowerShell (101 events — EIDs 4103, 4104):**

EID 4104 script block logging captures the test logic. The cleanup scriptblock reads: `& {reg.exe import "C:\AtomicRedTeam\atomics\T1547.001\src\SessionManagerBackup.reg"; Remove-Item -Path "C:\AtomicRedTeam\atomics\T1547.001\src\SessionManagerBackup.reg" -Force}`. The main test payload is captured in the EID 4688 command line rather than a distinct large EID 4104 block.

Compared to the defended variant (41 Sysmon, 12 Security, 38 PowerShell), the undefended run produces significantly more events (63 Sysmon, 6 Security, 101 PowerShell). The higher Sysmon count (63 vs. 41) reflects the 19 EID 13 events from the cleanup `reg.exe import` restoring the Session Manager environment variables — the defended run likely did not trigger as many registry writes during cleanup.

## What This Dataset Does Not Contain

- The actual `BootExecute` write (setting the value to `autocheck autoche *`) may be in the full dataset but is not in the EID 13 sample set. The `BootExecute` value is a `REG_MULTI_SZ` (multi-string) type, and the Sysmon `Details` field shows `Binary Data` for this type rather than a decoded string.
- No early-boot execution of any payload occurs. The system was not rebooted after modification.
- The contents of the exported `SessionManagerBackup.reg` file are not captured in any log channel.

## Assessment

This dataset provides complete telemetry for the `BootExecute` modification technique with the most direct observable — the full PowerShell command line including the `Set-ItemProperty` targeting `HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager` with name `BootExecute` — captured in both Sysmon EID 1 and Security EID 4688. The cleanup `reg.exe import` produces a large number of EID 13 registry write events that, while not directly related to the persistence action, demonstrate how a bulk registry restore creates a distinctive pattern in telemetry.

## Detection Opportunities Present in This Data

The following observable events in this dataset support detection:

- **Security EID 4688** recording `powershell.exe` with a command line containing `Session Manager` and `BootExecute` — the value name `BootExecute` in any process command line or script block is exceptional and warrants immediate investigation.

- **Security EID 4688** recording `reg.exe` with arguments `export "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager"` — creating a backup of the Session Manager key is a preparatory step that often precedes modification.

- **Sysmon EID 1** for `reg.exe` with `export` targeting `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager` — the same signal in Sysmon with process GUID correlation to the subsequent PowerShell `Set-ItemProperty` call.

- **Sysmon EID 13** with `TargetObject` containing `Session Manager\BootExecute` written by any user-mode process (`powershell.exe`, `reg.exe`, etc.) rather than the kernel — any such write is abnormal outside of OS upgrades or disk repair tools.

- **Sequential `reg.exe export` followed by `reg.exe import`** on the Session Manager path within a short time window — this backup-modify-restore pattern appears both here and in T1547.001-14/15, and it indicates automated testing or adversarial tooling rather than manual administration.
