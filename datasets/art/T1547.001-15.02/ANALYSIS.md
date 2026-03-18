# T1547.001-15: Registry Run Keys / Startup Folder — HKLM - Modify Default System Shell - Winlogon Shell KEY Value

## Technique Context

T1547.001 covers persistence and privilege escalation through Windows registry run keys and startup folder mechanisms. This test targets `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell`, which specifies the shell program Windows launches after logon completes. The standard value is `explorer.exe`. Like the `Userinit` key (T1547.001-14), `Shell` accepts a comma-separated list — every entry launches at logon alongside the user's normal desktop. An adversary who appends a malicious executable to this value achieves persistent execution with every interactive logon, with their payload running in the user's desktop session alongside `explorer.exe`.

This is a targeted modification of an existing, critical system value rather than a new registry key. The sysmon-modular ruleset classifies Winlogon key modifications under T1547.004 (Winlogon Helper DLL) rather than T1547.001, which is reflected in the rule annotations throughout this dataset.

This dataset was collected on ACME-WS06 (Windows 11 Enterprise Evaluation, domain `acme.local`) with Windows Defender fully disabled via Group Policy. Compare with the defended variant in `datasets/art/T1547.001-15` for the same test against an active Defender installation.

## What This Dataset Contains

The test executed as `NT AUTHORITY\SYSTEM` via QEMU guest agent. The payload reads the current `Shell` value (`explorer.exe`), saves it as `Shell-backup`, constructs a new value by appending `, C:\Windows\explorer.exe` (using `explorer.exe` itself as a benign stand-in), writes the modified value, and restores the original during cleanup.

**Sysmon (28 events — EIDs 1, 7, 10, 11, 13, 17):**

The registry modification is captured in two Sysmon EID 13 (RegistrySetValue) events, both annotated `RuleName: technique_id=T1547.004,technique_name=Winlogon Helper DLL`:

1. `powershell.exe` writing `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell-backup` with `Details: explorer.exe` — the backup of the original value saved before modification.
2. `powershell.exe` writing `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell` with `Details: explorer.exe, C:\Windows\explorer.exe` — the modified value with the appended shell entry visible in plaintext.

EID 1 (ProcessCreate) captures `whoami.exe` (tagged T1033) twice — the pre-execution identity check — and the child `powershell.exe` carrying the full test command line.

EID 7 (ImageLoad) accounts for 17 of 28 Sysmon events: .NET runtime DLLs and Defender platform DLLs loaded during PowerShell initialization. EID 10 (ProcessAccess), EID 11 (FileCreate for the PowerShell startup profile), and EID 17 (PipeCreate for the PSHost named pipe) complete the picture.

**Security (3 events — EID 4688):**

Three EID 4688 process creation events are recorded. The key entry is the child `powershell.exe` command line: `"powershell.exe" & {$oldvalue = $(Get-ItemPropertyValue -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "Shell"); Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "Shell-backup" -Value "$oldvalue"; $newvalue = $oldvalue + ", C:\Windows\explorer.exe"; Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "Shell" -Value "$newvalue"}` — the entire persistence logic is visible in this single event.

The two `whoami.exe` entries (EID 4688) confirm the process identity check ran twice: once at test start, once at cleanup. All processes ran as `NT AUTHORITY\SYSTEM`.

**PowerShell (101 events — EIDs 4103, 4104):**

EID 4104 script block logging captures the test payload. The substantive script blocks show the `Get-ItemPropertyValue` / `Set-ItemProperty` pattern targeting the `Shell` key.

The 97 EID 4104 events are predominantly PowerShell runtime boilerplate. EID 4103 events record `Set-ExecutionPolicy -Scope Process -Force` (ART test framework preamble).

Compared to the defended variant (28 Sysmon, 10 Security, 50 PowerShell), the undefended run produces fewer Security events (3 vs. 10), likely due to collection window differences, with a larger PowerShell event count (101 vs. 50) reflecting additional module loading activity.

## What This Dataset Does Not Contain

- The modified `Shell` value (`explorer.exe, C:\Windows\explorer.exe`) is captured in the EID 13 backup event — the appended modification is directly visible. The cleanup restoration also appears in EID 13.
- No logon session occurs after the modification. No process was spawned from the modified `Shell` value in this dataset.
- No Sysmon EID 13 carries a T1547.001 rule name; all Winlogon path writes are annotated as T1547.004 by sysmon-modular.
- No network activity is present.

## Assessment

This dataset provides clean, high-fidelity telemetry for the Winlogon `Shell` modification technique. The two EID 13 events directly show both the backup write and the modified value containing the appended shell path. The full `Set-ItemProperty` command targeting `Winlogon\Shell` is present in EID 4688 and in EID 4104 script block logging.

The undefended run (28 Sysmon, 3 Security, 101 PowerShell) differs from the defended run (28 Sysmon, 10 Security, 50 PowerShell) primarily in the Security event count and PowerShell volume. The Sysmon event count is identical, suggesting Defender's presence or absence does not materially affect the core registry modification telemetry. The reduced Security event count (3 vs. 10) in the undefended run likely reflects a narrower collection window rather than Defender suppression.

## Detection Opportunities Present in This Data

The following observable events in this dataset support detection:

- **Sysmon EID 13** with `TargetObject` containing `Winlogon\Shell` written by any process other than a trusted Windows system component. The backup value write (`Shell-backup`) is also a detectable pattern — legitimate tools do not create backup copies of this key.

- **Security EID 4688** recording `powershell.exe` with a command line referencing both `Winlogon` and `Set-ItemProperty` — the full payload is captured in the command line field at process creation time.

- **PowerShell EID 4104** script blocks containing `Winlogon\Shell` combined with `Set-ItemProperty` — plaintext capture of the modification logic with no obfuscation in this test.

- **Paired EID 13 events** targeting both `Shell` and `Shell-backup` (or `Userinit` and `Userinit-backup`) in rapid succession from the same process GUID — the ART test's backup-modify-restore pattern produces a distinctive double-write signature that differs from legitimate configuration changes.

- **Process context**: `powershell.exe` running as `NT AUTHORITY\SYSTEM` targeting Winlogon registry paths is an unusual combination that warrants investigation in any operational environment.
