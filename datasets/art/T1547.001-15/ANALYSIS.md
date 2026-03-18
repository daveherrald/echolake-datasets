# T1547.001-15: Registry Run Keys / Startup Folder — HKLM - Modify Default System Shell - Winlogon Shell KEY Value

## Technique Context

T1547.001 covers Registry Run Keys and Startup Folder persistence. This test modifies `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell`, which specifies the shell program that Windows launches after user logon. The standard value is `explorer.exe`. Windows supports comma-separated multiple shells — all listed programs will launch at logon. An adversary who appends a malicious executable to this value achieves persistent execution for every user logon, with the payload running alongside the user's normal shell session. Like the Userinit modification (T1547.001-14), this targets an existing critical value rather than adding new keys.

## What This Dataset Contains

The test executed from NT AUTHORITY\SYSTEM on ACME-WS02 (Windows 11 Enterprise, domain `acme.local`). The payload reads the current `Shell` value, saves a backup as `Shell-backup`, appends `, C:\Windows\explorer.exe` to the existing value (using `explorer.exe` itself as the benign payload), and writes it back.

**Sysmon (28 events — Event IDs 1, 7, 10, 11, 13, 17):**
- Two Sysmon Event ID 13 (RegistrySetValue) events are present, both tagged `technique_id=T1547.004,technique_name=Winlogon Helper DLL` (as with T1547.001-14, sysmon-modular classifies Winlogon key modifications under T1547.004):
  1. `TargetObject: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell-backup`, `Details: (Empty)` — the backup save before modification.
  2. `TargetObject: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell`, `Details: , C:\Windows\explorer.exe` — the modified value showing the appended shell entry.
- Sysmon Event ID 1 (ProcessCreate) captures `whoami.exe` (tagged `T1033`) and `powershell.exe` (tagged `T1059.001`).
- Sysmon Event ID 7 (ImageLoad), Event ID 10 (ProcessAccess), Event ID 11 (FileCreate), and Event ID 17 (PipeCreate) are standard PowerShell initialization artifacts.
- This dataset has fewer Sysmon events (28) than T1547.001-14 (48), reflecting a simpler execution path — no WMI invocation and less module loading activity.

**Security (10 events — Event IDs 4688, 4689, 4703):**
- Event ID 4688 records `powershell.exe` and `whoami.exe`. The PowerShell commandline references `Winlogon\Shell` and the append operation with `Get-ItemPropertyValue` and `Set-ItemProperty`.
- Event ID 4689 records process exits.
- Event ID 4703 records a token right adjustment.

**PowerShell (50 events — Event IDs 4100, 4102, 4103, 4104):**
- As with T1547.001-14, this dataset includes Event IDs 4100 and 4102, indicating a runtime error or pipeline completion event was logged during test execution.
- Event ID 4104 captures the full payload in both wrapper and body forms: reading `Shell` via `Get-ItemPropertyValue`, saving backup with `Set-ItemProperty`, constructing `$newvalue = $oldvalue + ", C:\Windows\explorer.exe"`, and writing it back.
- Event ID 4103 records `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass`.
- An empty profile script at the systemprofile path is logged.
- Remaining 4104 events are runtime boilerplate.

## What This Dataset Does Not Contain

- No logon trigger or execution of the modified shell — persistence registered but not triggered.
- No Defender block events. Using `explorer.exe` as the payload did not trigger Defender.
- No network events.
- Object access auditing is disabled.
- The cleanup step (restoring `Shell` from `Shell-backup`) would require a separate test execution.

## Assessment

This dataset, paired with T1547.001-14, represents the two most critical Winlogon modification techniques in the T1547.001 series. Both target values that are fundamental to Windows logon operation — modification of either `Userinit` or `Shell` affects every user logon. Sysmon Event ID 13 directly captures both the backup and the modification, and both are tagged T1547.004. The appended value `, C:\Windows\explorer.exe` is benign in this test; in a real attack this would be a malicious executable path. The PowerShell script block provides the full modification logic for forensic reconstruction.

## Detection Opportunities Present in This Data

- **Sysmon Event ID 13**: `SetValue` on `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell` — any write to this value outside of Windows setup or legitimate system management is highly suspicious. Sysmon-modular tags this as T1547.004.
- **Sysmon Event ID 13**: Creation of `Shell-backup` (as with `Userinit-backup` in test -14) indicates a script is saving the existing value before modification — a behavioral pattern common to well-written attack tooling and ART tests alike.
- **Security Event ID 4688**: `powershell.exe` command lines referencing `Winlogon\Shell` and `Set-ItemProperty`.
- **PowerShell Event ID 4104**: Script blocks that read `Winlogon` shell values and append executable paths to them.
- **Alerting threshold**: The `Shell` value should contain only `explorer.exe` in standard configurations. Any additional comma-separated entries should trigger immediate review.
- **Events 4100/4102**: Present in both T1547.001-14 and -15, these signal that the PowerShell engine logged an error or pipeline event during Winlogon key manipulation. Correlating these with Sysmon ID 13 Winlogon writes strengthens detection confidence.
- **Combined T1547.004 pattern**: Detecting both `Userinit` and `Shell` modifications in close temporal proximity (as would occur if an adversary modified both) is a strong indicator of a systematic Winlogon persistence setup.
