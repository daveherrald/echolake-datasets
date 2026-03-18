# T1547-3: Boot or Logon Autostart Execution — Leverage Virtual Channels to Execute Custom DLL During Successful RDP Session

## Technique Context

T1547 covers Boot or Logon Autostart Execution. This test exercises a persistence mechanism via RDP Virtual Channel Add-ins. Windows Terminal Services allows custom DLLs to be registered as virtual channel add-ins under `HKCU\Software\Microsoft\Terminal Server Client\Default\Addins\<name>` with a `Name` value pointing to a DLL path. These add-ins are loaded into the RDP client process when an RDP session is established. An adversary who registers a malicious DLL here achieves code execution whenever the compromised user initiates an RDP connection, making this a persistence mechanism tied to logon behavior rather than system boot.

## What This Dataset Contains

The test executed from NT AUTHORITY\SYSTEM on ACME-WS02 (Windows 11 Enterprise, domain `acme.local`). The ART test framework writes a registry key via `cmd.exe /c reg add` to set up the virtual channel add-in entry, using `C:\Windows\System32\amsi.dll` as the payload DLL path (a benign system DLL used as a stand-in).

**Sysmon (17 events — Event IDs 1, 7, 10, 11, 17):**
- Sysmon Event ID 1 (ProcessCreate) captures `whoami.exe` (tagged `technique_id=T1033`), `cmd.exe` (tagged `technique_id=T1059.003`) with the full command line `"cmd.exe" /c reg add "HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default\Addins\Malware" /v Name /t REG_SZ /d "C:\Windows\System32\amsi.dll" /f`, and `reg.exe` (tagged `technique_id=T1012`) with the same full registry add command. The use of `T1012` (Query Registry) as the Sysmon rule label for `reg.exe` is a sysmon-modular rule name that fires on `reg.exe` regardless of the operation type.
- Sysmon Event ID 7 (ImageLoad) records .NET runtime DLLs and Defender DLLs loading into two distinct `powershell.exe` instances — the outer ART test framework and the inner test execution shell.
- Sysmon Event ID 10 (ProcessAccess) records `powershell.exe` accessing `whoami.exe` and `cmd.exe` child processes, tagged `technique_id=T1055.001`.
- Sysmon Event ID 11 (FileCreate) records PowerShell startup profile data files.
- Sysmon Event ID 17 (PipeCreate) records PowerShell named pipes.
- There is no Sysmon Event ID 13 (RegistrySetValue) in this dataset. The registry write was performed by `reg.exe` (a command-line tool), and the sysmon-modular configuration did not capture the resulting value set under this key path.

**Security (13 events — Event IDs 4688, 4689, 4703):**
- Event ID 4688 records process creation for `whoami.exe`, `cmd.exe`, and `reg.exe`, all running as SYSTEM. The `cmd.exe` and `reg.exe` entries include the full command line showing the terminal server client addins registry path and `amsi.dll` as the registered DLL.
- Event ID 4689 records corresponding exits.
- Event ID 4703 records a token right adjustment for the PowerShell process.

**PowerShell (34 events — Event IDs 4103, 4104):**
- Event ID 4103 records two `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass` invocations — the ART test framework boilerplate.
- All Event ID 4104 blocks are runtime error-handling boilerplate (`$_.PSMessageDetails`, `$_.ErrorCategory_Message`, etc.). No substantive 4104 script block content for the test payload is present because the actual operation was executed via `cmd.exe /c reg add` rather than PowerShell cmdlets.

## What This Dataset Does Not Contain

- No Sysmon Event ID 13 (RegistrySetValue). The registry modification was performed by `reg.exe`, and the specific key path (`HKCU\Software\Microsoft\Terminal Server Client\Default\Addins\`) was not included in the sysmon-modular include rules for registry monitoring. The registry write is only evidenced by the `reg.exe` command line.
- No evidence of RDP session establishment or DLL loading. This test only registers the persistence mechanism; it does not trigger it. Observing the add-in DLL being loaded into the RDP client process would require an active RDP session and would appear in Sysmon Event ID 7.
- No Defender block events. The registration of `amsi.dll` (a legitimate system DLL) was not flagged.
- No network events. No RDP connection was made.
- No Event ID 4656/4663 (object access auditing). Registry object access policy is set to none.

## Assessment

This dataset captures the persistence registration step for RDP virtual channel add-in abuse. The key evidence is the `reg.exe` command line in Security Event ID 4688, which shows the exact registry path and DLL being registered. In a real attack, the DLL path would point to a malicious library rather than `amsi.dll`. The absence of Sysmon Event ID 13 for this registry path means that registry-based detection must rely on command-line monitoring rather than Sysmon's registry event stream for this technique as configured.

## Detection Opportunities Present in This Data

- **Security Event ID 4688**: `reg.exe` or `reg add` command lines referencing `HKCU\Software\Microsoft\Terminal Server Client\Default\Addins\` — this registry path is rarely legitimately modified by scripting or command-line tools.
- **Security Event ID 4688**: `cmd.exe` spawning `reg.exe` with terminal server client registry paths, particularly when the parent chain includes PowerShell or WMI.
- **Sysmon Event ID 1**: `cmd.exe` command line containing both `Terminal Server Client` and `Addins` path components.
- **Sysmon Event ID 1**: `reg.exe` invocations from non-interactive processes (running as SYSTEM or under WMI/remote execution contexts).
- **Sysmon Event ID 7**: (would require an RDP trigger) DLL load events showing unexpected DLLs loading into `mstsc.exe` at session establishment time would indicate add-in execution.
- Enabling Sysmon Event ID 13 for the `HKCU\Software\Microsoft\Terminal Server Client\` key path would provide direct registry-level detection not present in this dataset.
