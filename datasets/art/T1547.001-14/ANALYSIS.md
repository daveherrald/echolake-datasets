# T1547.001-14: Registry Run Keys / Startup Folder — HKLM - Append Command to Winlogon Userinit KEY Value

## Technique Context

T1547.001 covers Registry Run Keys and Startup Folder persistence. This test modifies `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit`, a registry value that specifies the program Windows runs after a user logs on before the shell is launched. The standard value is `C:\Windows\system32\userinit.exe,`. An adversary can append additional executables to this comma-separated list; all listed programs run during logon. This technique does not add a new registry key — it modifies an existing, critical one — which makes it more evasive than adding a new Run key entry and potentially more dangerous, as modifying this value incorrectly can prevent logon.

## What This Dataset Contains

The test executed from NT AUTHORITY\SYSTEM on ACME-WS02 (Windows 11 Enterprise, domain `acme.local`). The payload reads the current `Userinit` value, saves a backup as `Userinit-backup`, appends ` C:\Windows\System32\calc.exe` to the existing value, and writes it back.

**Sysmon (48 events — Event IDs 1, 7, 10, 11, 13, 17):**
- Two Sysmon Event ID 13 (RegistrySetValue) events are present, both tagged `technique_id=T1547.004,technique_name=Winlogon Helper DLL` (not T1547.001 — the sysmon-modular rules classify Winlogon modifications under T1547.004):
  1. `TargetObject: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit-backup`, `Details: (Empty)` — the backup save before modification.
  2. `TargetObject: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit`, `Details: C:\Windows\System32\calc.exe` — the modified value. Note: the data shows only the appended portion because the Sysmon event appears to record the final written data truncated or the original value was already `userinit.exe,` followed by the append.
- Sysmon Event ID 1 (ProcessCreate) captures `whoami.exe` (tagged `T1033`) and `powershell.exe` (tagged `T1059.001`).
- Sysmon Event ID 7 (ImageLoad), Event ID 10 (ProcessAccess), Event ID 11 (FileCreate), and Event ID 17 (PipeCreate) are standard PowerShell initialization artifacts.

**Security (10 events — Event IDs 4688, 4689, 4703):**
- Event ID 4688 records `powershell.exe` and `whoami.exe`. The PowerShell entry shows the full command line referencing `Winlogon\Userinit` and the append logic.
- Event ID 4689 and Event ID 4703 complete the process lifecycle entries.

**PowerShell (53 events — Event IDs 4100, 4102, 4103, 4104):**
- This dataset includes Event ID 4100 and Event ID 4102, which are not present in most other tests in this series. Event ID 4100 (`Error Message from PowerShell host`) and Event ID 4102 (`Pipeline execution details for command`) indicate that the script block encountered a runtime error or warning condition during execution, which triggered these additional logging events.
- Event ID 4104 captures the full test payload: reading `Userinit` with `Get-ItemPropertyValue`, saving a backup with `Set-ItemProperty`, constructing the new value by appending ` C:\Windows\System32\calc.exe`, and writing it back. Both the outer wrapper and inner body script blocks are logged.
- Event ID 4103 records `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass`.
- One large 4104 block (multiple parts) contains a loaded PowerShell module (`MSFT_NetRoute.cdxml`) — this reflects module loading for network-related cmdlets that the test environment loaded as part of normal PowerShell initialization.
- Remaining 4104 events are runtime boilerplate.

## What This Dataset Does Not Contain

- No logon trigger or execution of `calc.exe` — persistence registered but not triggered.
- No Defender block events.
- No network events.
- Object access auditing is disabled.
- The cleanup step (restoring `Userinit` from `Userinit-backup`) would be a separate test execution; this dataset captures only the modification.

## Assessment

This dataset captures one of the more sensitive persistence mechanisms in the T1547.001 series — modification of the Winlogon Userinit value. Two Sysmon Event ID 13 entries directly record both the backup creation and the modification, though they are tagged T1547.004 (Winlogon Helper DLL) by the sysmon-modular rules rather than T1547.001, reflecting the classification ambiguity around Winlogon modifications. The PowerShell script block provides the complete append logic. The presence of Events 4100 and 4102 suggests a non-fatal error occurred during the test, possibly related to module loading.

## Detection Opportunities Present in This Data

- **Sysmon Event ID 13**: `SetValue` on `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit` — any write to this value by a process other than the Windows setup or legitimate configuration tools is a critical indicator. Sysmon-modular tags this as T1547.004.
- **Sysmon Event ID 13**: Creation of `Userinit-backup` is itself an indicator — adversaries sometimes leave backup artifacts that betray their modification pattern.
- **Security Event ID 4688**: `powershell.exe` command lines referencing `Winlogon` and `Userinit` together.
- **PowerShell Event ID 4104**: Script blocks reading `Userinit` value and appending executable paths to it.
- **Alerting threshold**: The `Userinit` value should contain only `C:\Windows\system32\userinit.exe,` in standard configurations. Any deviation — particularly appended paths — warrants immediate investigation.
- **Event IDs 4100/4102**: Their presence alongside test activity suggests the PowerShell host logged an error; in detection contexts these can provide additional forensic detail about what a script attempted.
