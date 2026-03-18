# T1547.001-14: Registry Run Keys / Startup Folder — HKLM - Append Command to Winlogon Userinit KEY Value

## Technique Context

T1547.001 covers persistence and privilege escalation through Windows registry run keys and startup folder mechanisms. This specific test targets `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit`, a registry value that controls which program Windows executes after user authentication and before the shell launches. The standard value is `C:\Windows\system32\userinit.exe,`. Windows parses this as a comma-separated list and runs every entry — an adversary who appends an additional executable achieves persistent execution at every logon without adding a new registry key, making the modification harder to spot than a new `Run` key entry.

This is a more invasive modification than a standard run key. Corrupting the `Userinit` value can prevent any user from logging on, so adversaries who use this technique must handle it carefully. The sysmon-modular ruleset classifies Winlogon modifications under `T1547.004` (Winlogon Helper DLL) rather than `T1547.001`, which is reflected in the rule annotations in this dataset.

This dataset was collected on ACME-WS06 (Windows 11 Enterprise Evaluation, domain `acme.local`) with Windows Defender fully disabled via Group Policy. Compare with the defended variant in `datasets/art/T1547.001-14` for the same technique executed against an active Defender installation.

## What This Dataset Contains

The test executed as `NT AUTHORITY\SYSTEM` via QEMU guest agent. The payload reads the current `Userinit` value, saves it as `Userinit-backup`, constructs a new value by appending ` C:\Windows\System32\calc.exe`, writes it back, then restores the original value during cleanup.

**Sysmon (41 events — EIDs 1, 7, 10, 11, 12, 13, 17):**

The central persistence action is captured in Sysmon EID 13 (RegistrySetValue):
- `powershell.exe` writing `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit` with `Details: C:\Windows\system32\userinit.exe,` — this reflects the cleanup restoration of the original value. The modification phase wrote the appended value (including `calc.exe`) but the captured EID 13 in the sample set shows the restore. The EID 12 (RegistryDeleteValue) event captures the deletion of the `Userinit-backup` key: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit-backup`.

Both registry events carry `RuleName: technique_id=T1547.004,technique_name=Winlogon Helper DLL` — the sysmon-modular configuration routes Winlogon path modifications to this rule, not T1547.001.

EID 1 (ProcessCreate) captures the child `powershell.exe` process with its full command line visible in Security EID 4688 (see below), and `whoami.exe` tagged `T1033`.

EID 10 (ProcessAccess) shows the parent `powershell.exe` (PID 17412) opening the child `whoami.exe` (PID 18328) with `GrantedAccess: 0x1fffff` — standard ART test framework behavior.

EID 7 (ImageLoad) produces 25 events covering .NET runtime DLL loads (`mscoree.dll`, `clr.dll`, `clrjit.dll`, `mscorlib.ni.dll`) tagged T1055 and T1574.002, plus `MpOAV.dll` and `MpClient.dll` from the disabled Defender platform directory. These are routine PowerShell initialization artifacts.

**Security (4 events — EID 4688):**

Four EID 4688 process creation events are present. The two most significant:

- `cmd.exe` → `powershell.exe` with full command line: `"powershell.exe" & {$oldvalue = $(Get-ItemPropertyValue -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "Userinit"); Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "Userinit-backup" -Value "$oldvalue"; $newvalue = $oldvalue + " C:\Windows\System32\calc.exe"; Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "Userinit" -Value "$newvalue"}` — this is the full persistence action in a single logged command line.

- A second `powershell.exe` for the cleanup: restoring `Userinit` from the backup and removing the backup key.

All four processes ran as `NT AUTHORITY\SYSTEM` (SubjectUserSid `S-1-5-18`, MandatoryLabel `S-1-16-16384`).

**PowerShell (106 events — EIDs 4103, 4104):**

Script block logging captures the test payload in full across multiple EID 4104 events. The substantive cleanup scriptblock reads: `& {$oldvalue = $(Get-ItemPropertyValue -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name 'Userinit-backup'); Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "Userinit" -Value "$oldvalue"; Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name 'Userinit-backup'}`.

The majority of EID 4104 events are PowerShell runtime boilerplate: error-handler stubs (`{ Set-StrictMode -Version 1; $_.PSMessageDetails }`), invoked during module loading. EID 4103 events record `Set-ExecutionPolicy -Scope Process -Force` (ART test framework preamble).

The high event count (106 vs. 53 in the defended variant) reflects additional PowerShell module loading activity in this execution. With Defender disabled, the execution path differs slightly as the AMSI hook is absent.

## What This Dataset Does Not Contain

- The actual appended `Userinit` value (`C:\Windows\system32\userinit.exe, C:\Windows\System32\calc.exe`) is not present as a distinct EID 13 event in the sample set — the sample captures the cleanup write, not the initial modification. The full dataset file (`data/sysmon.jsonl`) contains all 41 events and may include the initial write.
- No execution of `calc.exe` at logon occurs. The system was not logged off and back on during the test window.
- No Sysmon EID 13 is annotated with a T1547.001 rule name — the sysmon-modular configuration routes all Winlogon path writes to T1547.004 rules.
- No network activity is present; this technique requires no outbound connections.

## Assessment

This dataset is a complete and high-fidelity capture of the Winlogon `Userinit` modification technique. Compared to the defended variant (48 Sysmon, 10 Security, 53 PowerShell events), the undefended run produces fewer overall events (41 Sysmon, 4 Security, 106 PowerShell) with notable differences in the Security channel — the defended run produces 10 Security events (including EID 4689 and 4703) while the undefended run captures only 4. This likely reflects differences in the Cribl Edge collection window boundaries rather than Defender interference.

The PowerShell channel is substantially larger in the undefended run (106 vs. 53 events), capturing more module loading scriptblocks. With AMSI disabled, no script block interception occurs at the AMSI layer — all script blocks flow through to the PowerShell operational log unchanged.

The key forensic artifacts — the `Set-ItemProperty` command line in EID 4688, the EID 13 registry write to `Winlogon\Userinit`, and the full payload script block in EID 4104 — are all present and unambiguous.

## Detection Opportunities Present in This Data

The following observable events in this dataset support detection:

- **Sysmon EID 13** with `TargetObject` matching `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit` or `Winlogon\Shell`. Any write to these paths from a process other than a trusted Windows component during a scheduled maintenance window is suspicious.

- **Security EID 4688** recording `powershell.exe` with a command line containing `Winlogon` and `Set-ItemProperty` or `Get-ItemPropertyValue` — the full payload is in the command line field.

- **PowerShell EID 4104** script block content containing `Winlogon\Userinit` combined with `Set-ItemProperty` — this combination has essentially no legitimate administrative use and fires with full plaintext content in this dataset.

- **Sysmon EID 12/13** events creating or deleting a `Userinit-backup` or `Shell-backup` key — the test's backup/restore pattern leaves a characteristic double-write signature.

- **Process ancestry**: `powershell.exe` (parent PID 17412) spawning a child `powershell.exe` running a `Set-ItemProperty` scriptblock targeting Winlogon paths while running as `NT AUTHORITY\SYSTEM`.
