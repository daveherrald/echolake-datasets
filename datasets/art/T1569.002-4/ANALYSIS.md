# T1569.002-4: Service Execution — BlackCat pre-encryption cmds with Lateral Movement

## Technique Context

T1569.002 (Service Execution) test 4 replicates the pre-encryption command sequence documented
in BlackCat (ALPHV) ransomware investigations. Before encrypting files, BlackCat operators
execute a series of preparatory commands to maximize encryption scope and enable lateral
movement: querying system identity (`wmic csproduct get UUID`), enabling symlink evaluation
across paths (`fsutil behavior set SymlinkEvaluation`), increasing SMB connection limits
(`reg add ... LanmanServer\Parameters MaxMpxCt`), and staging PsExec for remote execution.
This test does not perform encryption — it exercises only the preparation phase.

## What This Dataset Contains

The dataset spans approximately 6 seconds (14:30:29–14:30:35 UTC) from ACME-WS02.

**PowerShell 4104 (Script Block Logging)** captures the full command sequence:

```
cmd.exe /c "wmic    csproduct   get UUID"
cmd.exe /c "fsutil behavior   set SymlinkEvaluation R2L:1"
cmd.exe /c "fsutil behavior set  SymlinkEvaluation R2R:1"
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters /v MaxMpxCt /d 65535 /t REG_DWORD /f
copy "C:\AtomicRedTeam\atomics\..\ExternalPayloads\PsExec.exe" $env:temp
cmd.exe /c "$env:temp\psexec.exe  -accepteula  \\$ENV:COMPUTERNAME cmd.exe  /c echo "--access-token""
```

Note the extra whitespace in command arguments (e.g., `wmic \tcsproduct \tget UUID`). This
is characteristic of the real BlackCat samples, which used irregular spacing likely to evade
simple string-match rules on specific command formats.

**Sysmon Event 1 (Process Create)** captures the full child process chain:
- `powershell.exe` with the multi-command block (tagged T1083 — `New-Item` directory reference
  in the command start)
- `cmd.exe /c "wmic csproduct get UUID"` (tagged T1059.003)
- `cmd.exe /c "fsutil behavior set SymlinkEvaluation R2L:1"` (tagged T1059.003)
- `fsutil.exe behavior set SymlinkEvaluation R2L:1` (tagged T1070 Indicator Removal)
- `cmd.exe /c "fsutil behavior set SymlinkEvaluation R2R:1"` (tagged T1059.003)
- `fsutil.exe behavior set SymlinkEvaluation R2R:1` (tagged T1070)
- `reg.exe add HKEY_LOCAL_MACHINE\SYSTEM\...\LanmanServer\Parameters /v MaxMpxCt /d 65535 /t REG_DWORD /f` (tagged T1083)
- `cmd.exe /c "C:\Windows\TEMP\psexec.exe -accepteula \\ACME-WS02 cmd.exe /c echo --access-token"` (tagged T1059.003)

**Sysmon Event 13 (Registry Value Set)** captures the `reg.exe` write:
`HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters\MaxMpxCt` = `DWORD 0x0000ffff` (65535).

**Security 4688/4689** record process lifecycle for `powershell.exe`, `whoami.exe`, `cmd.exe`,
`fsutil.exe`, and `reg.exe` under SYSTEM.

## What This Dataset Does Not Contain (and Why)

**No wmic.exe process create in Sysmon.** `wmic.exe` is not in the sysmon-modular include-mode
process create rules for this configuration. The command runs inside `cmd.exe` which is
captured, but `wmic.exe` itself does not appear as a Sysmon Event 1. Security 4688 should
capture it but it is absent from the bundled security events.

**No PsExec execution evidence beyond process create for cmd.exe.** The `cmd.exe /c psexec.exe`
process is captured in Sysmon Event 1, but there is no evidence of PsExec completing — no
service installation, no network events, no `calc.exe` or `echo` output. This is consistent
with Defender blocking PsExec (see T1569.002-2 analysis).

**No file copy event for PsExec.exe.** The `copy ... PsExec.exe $env:temp` command runs via
PowerShell's copy semantics, but no Sysmon Event 11 for `C:\Windows\TEMP\psexec.exe` appears.
The sysmon-modular rules do not include file creation events in TEMP for arbitrary executables.

**No System log events.** The System log is not collected in this dataset, so there are no
Service Installation (7045) or other system service events.

## Assessment

This dataset is valuable for the fidelity of the BlackCat pre-encryption pattern. The
combination of: irregular-spacing `wmic` commands, `fsutil SymlinkEvaluation` changes, the
specific `LanmanServer MaxMpxCt 65535` registry write, and PsExec staging into `%TEMP%`
constitutes a recognizable multi-step threat actor behavioral cluster. Each step has
individually documented detection logic; seen together they raise confidence significantly.

The `reg.exe` registry write to `MaxMpxCt` is particularly distinctive: setting maximum
multiplexed SMB requests to 65535 is a pre-lateral-movement optimization with no legitimate
administrative purpose at that value.

## Detection Opportunities Present in This Data

- **PowerShell 4104**: The combined presence of `wmic csproduct get UUID`, `fsutil behavior
  set SymlinkEvaluation`, and `LanmanServer\Parameters MaxMpxCt 65535` in a single script
  block matches the documented BlackCat pre-encryption playbook.

- **Sysmon Event 13**: `reg.exe` writing `MaxMpxCt` to `HKLM\...\LanmanServer\Parameters`
  with value `0xffff` is a high-specificity indicator. Legitimate SMB tuning uses values
  well below 65535.

- **Sysmon Event 1**: `fsutil.exe behavior set SymlinkEvaluation R2L:1` or `R2R:1` is
  anomalous on managed workstations. Tagged T1070 by sysmon-modular.

- **Security 4688**: Sequential process creation of `wmic.exe`, `fsutil.exe`, `reg.exe`,
  and `psexec.exe` (or `cmd.exe` invoking each) within seconds from the same parent process
  is a behavioral cluster rule opportunity.

- **Sysmon Event 1 (cmd.exe parent)**: `psexec.exe -accepteula \\<hostname> cmd.exe` with
  `--access-token` or similar dummy argument from a TEMP directory path.
