# T1547.001-17: Registry Run Keys / Startup Folder — Modify BootExecute Value

## Technique Context

MITRE ATT&CK T1547.001 covers persistence through registry run keys and startup mechanisms. The `BootExecute` value under `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager` specifies programs that run during early Windows initialization — before most user-mode services start and before the typical logon process. By default this value contains `autocheck autochk *`, which runs disk integrity checks. Adversaries who modify `BootExecute` can register a program to execute with extremely early timing and elevated privilege, making it difficult for standard endpoint tools to intercept or clean up.

## What This Dataset Contains

This dataset captures telemetry from the Atomic Red Team test that modifies the `BootExecute` registry value using PowerShell's `Set-ItemProperty` cmdlet. The test first creates a backup of the `Session Manager` key using `reg.exe export`, then appends a new executable reference to the `BootExecute` binary data value.

**Sysmon (41 events):**
- EID 1 (Process Create): `whoami.exe` (test framework identity check). A child `powershell.exe` spawned with the full test command line referencing the `SessionManager` backup and `Set-ItemProperty` call targeting `BootExecute`. `reg.exe` spawned by the child PowerShell to export the backup: `"C:\Windows\system32\reg.exe" export "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" C:\AtomicRedTeam\atomics\T1547.001\src\SessionManagerBackup.reg /y`.
- EID 7 (Image Load): DLL loads for both PowerShell processes and `reg.exe` — standard runtime behavior.
- EID 10 (Process Access): PowerShell accessing `whoami.exe`.
- EID 11 (File Create): `reg.exe` creating the backup `.reg` file. PowerShell startup profile data file.
- EID 13 (Registry Value Set): PowerShell (`powershell.exe`) writing to `HKLM\System\CurrentControlSet\Control\Session Manager\BootExecute`. The Details field shows `Binary Data` — the value is a REG_MULTI_SZ type containing the modified boot execute list. Rule annotated as `technique_id=T1547.001`.
- EID 17 (Pipe Create): Named pipe from PowerShell.

**Security (12 events):**
- EID 4688/4689: Process creates and exits for both PowerShell instances, `whoami.exe`, `reg.exe`, and `conhost.exe`. The 4688 event for the child PowerShell records the full command line including the conditional backup check and the `Set-ItemProperty` call to `BootExecute`. The `reg.exe` event records the export command.
- EID 4703: Token right adjustment for PowerShell.

**PowerShell (38 events):**
- EID 4104 (Script Block Logging): Two substantive scriptblocks: the outer wrapper starting with `& {if (!(Test-Path "C:\AtomicRedTeam\atomics\T1547.001\src\SessionManagerBackup.reg")) { reg.exe export ... }; Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "BootExecute" ...}` and the inner body. The full `Set-ItemProperty` invocation targeting `BootExecute` is captured in plaintext.
- EID 4103: `Set-ExecutionPolicy -Scope Process -Force` (test framework preamble, appears twice).
- Remainder are PowerShell runtime boilerplate scriptblocks.

## What This Dataset Does Not Contain

- The new value written to `BootExecute` is captured as `Binary Data` in Sysmon EID 13 — the actual binary content of the modified MULTI_SZ value is not decoded or shown. The specific executable registered in `BootExecute` cannot be determined from the Sysmon event alone.
- No boot-time execution of the registered program occurs — the system was not rebooted during or after test execution, so there is no second-stage telemetry from the `BootExecute` payload.
- No Defender block occurred (`0xC0000022` access denied) for the registry write. The `BootExecute` value under `Session Manager` is writable by SYSTEM without restriction.
- No network connection events appear in this dataset.

## Assessment

The test completed. Sysmon EID 13 records the `BootExecute` write with the target object path and flags it with the T1547.001 rule. The PowerShell EID 4104 scriptblock captures the `Set-ItemProperty` call in full. However, the actual content written to `BootExecute` is recorded only as `Binary Data` in Sysmon — the specific executable that would run at boot is not visible without additional forensics on the registry value itself.

The `reg.exe export` backup step is an interesting indicator: it suggests the test (or a real adversary using this technique) is preserving the original value to enable later cleanup. Detection of `reg.exe export` targeting `Session Manager` followed closely by a `BootExecute` modification may be a useful composite signal.

## Detection Opportunities Present in This Data

- **Sysmon EID 13**: Any modification to `HKLM\System\CurrentControlSet\Control\Session Manager\BootExecute` by any process other than the Windows OS updater or trusted system components is a high-priority alert. This value is rarely modified legitimately.
- **PowerShell EID 4104**: Script block containing `Set-ItemProperty` (or `New-ItemProperty`) targeting `BootExecute` under `Session Manager` is a direct indicator.
- **Security EID 4688**: Child PowerShell command line including `BootExecute` in the argument string.
- **Sysmon EID 1**: `reg.exe export "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager"` immediately preceding a `BootExecute` modification is a contextual indicator of adversarial cleanup preparation.
- **Pattern**: Any write to `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute` — regardless of the writing process — should trigger immediate investigation given the extreme early-execution privilege it confers.
