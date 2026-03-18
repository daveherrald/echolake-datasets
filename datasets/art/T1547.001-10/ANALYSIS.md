# T1547.001-10: Registry Run Keys / Startup Folder — Change Startup Folder - HKLM Modify User Shell Folders Common Startup Value

## Technique Context

T1547.001 covers Registry Run Keys and Startup Folder persistence. Rather than adding a new Run key entry, this test modifies the registry value that defines where Windows looks for the Common Startup folder itself. The `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders` key contains a value named `Common Startup` which tells Windows where to find startup items that apply to all users. By redirecting this value to an attacker-controlled directory populated with malicious executables, an adversary can cause those executables to run at logon for every user on the system without adding traditional Run key entries that security tools monitor closely.

## What This Dataset Contains

The test executed from NT AUTHORITY\SYSTEM on ACME-WS02 (Windows 11 Enterprise, domain `acme.local`). The payload creates `C:\Windows\Temp\atomictest\`, copies `calc.exe` into it, and then sets the `Common Startup` value to point to that directory via `Set-ItemProperty`.

**Sysmon (32 events — Event IDs 1, 7, 10, 11, 17, 29):**
- Sysmon Event ID 1 (ProcessCreate) captures `WmiPrvSE.exe` (tagged `technique_id=T1047`), `whoami.exe` (tagged `technique_id=T1033`), and `powershell.exe` (tagged `technique_id=T1083` — matching because the commandline contained `New-Item`) spawned by the test framework.
- Sysmon Event ID 29 (FileExecutableDetected) records `C:\Windows\Temp\atomictest\calc.exe` being written to the redirected startup directory, tagged `technique_id=T1059.001`. This event fires when Sysmon detects a new executable file created by `powershell.exe` via `Copy-Item`. Hashes are recorded: SHA256=`9C2C8A8588FE6DB09C09337E78437CB056CD557DB1BCF5240112CBFB7B600EFB`. This is a significant artifact — it records both the file and its hash, making it useful for integrity verification.
- Sysmon Event ID 11 (FileCreate) records the creation of the `atomictest` directory marker and the `calc.exe` copy in `C:\Windows\Temp\atomictest\`.
- Sysmon Event ID 7 (ImageLoad) records standard .NET runtime and Defender DLL loads into both PowerShell instances.
- Sysmon Event ID 10 (ProcessAccess) records the parent PowerShell accessing child processes, tagged `T1055.001`.
- Sysmon Event ID 17 (PipeCreate) records PowerShell named pipes.
- **No Sysmon Event ID 13 (RegistrySetValue)** for the `Common Startup` value modification — the sysmon-modular include rules did not match `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders\Common Startup` in this configuration.

**Security (16 events — Event IDs 4624, 4627, 4672, 4688, 4689, 4703):**
- Event ID 4688 records process creation for `WmiPrvSE.exe`, `powershell.exe`, and `whoami.exe`. The `powershell.exe` entry shows the full command line: `"powershell.exe" & {New-Item -ItemType Directory -path "$env:TMP\atomictest\"...Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "Common Startup" -Value "$env:TMP\atomictest\"}`
- Event ID 4624 (Logon Type 5 — Service) and Event ID 4627 (group membership) record the WMI-triggered service logon.
- Event ID 4672 records special privileges including SeLoadDriverPrivilege and SeDebugPrivilege assigned to the SYSTEM logon.
- Event ID 4703 records token right adjustments.

**PowerShell (40 events — Event IDs 4103, 4104):**
- Event ID 4104 captures the complete ART test payload in two forms: the outer wrapper `& {New-Item -ItemType Directory ... Copy-Item ... Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "Common Startup" -Value "$env:TMP\atomictest\"}` and the inner script body without the `&` wrapper.
- Event ID 4103 records `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass` for both PowerShell instances.
- Remaining 4104 events are PowerShell runtime boilerplate.
- A profile script at `C:\Windows\system32\config\systemprofile\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1` is logged as empty.

## What This Dataset Does Not Contain

- No Sysmon Event ID 13 for the `Common Startup` registry modification. The persistence registration step is only visible through the PowerShell command line in Security Event ID 4688 and the script block in Event ID 4104.
- No evidence of the redirected startup folder being honored at logon — the test does not trigger a logon.
- No Defender block events. The operation completed successfully.
- No network events.
- Object access auditing is disabled; no Event ID 4656/4663 for file or registry operations.

## Assessment

This dataset provides good coverage of the attack's setup phase: the directory creation, executable staging, and registry modification are all reconstructible from the available evidence, with the PowerShell command line and script block logging providing the clearest picture. The Sysmon Event ID 29 (FileExecutableDetected) for `calc.exe` is an interesting additional artifact. The central persistence artifact — the `Common Startup` registry value modification — is only evidenced through process command-line data, not through a dedicated registry event.

## Detection Opportunities Present in This Data

- **Security Event ID 4688 / PowerShell Event ID 4104**: `Set-ItemProperty` targeting `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders` with the `Common Startup` name — this specific combination is highly anomalous in normal operations.
- **Sysmon Event ID 29 (FileExecutableDetected)**: Executable files being created in non-standard directories, particularly under `%TEMP%` or paths outside normal program installation locations, by scripting hosts.
- **Sysmon Event ID 11**: Creation of `calc.exe` or other executables in user temp directories by `powershell.exe`.
- **Security Event ID 4688**: `powershell.exe` command lines containing `User Shell Folders` and `Common Startup`.
- **PowerShell Event ID 4104**: Script blocks that both create files in a new directory and then modify a shell folder registry value in the same execution context.
- Enabling Sysmon Event ID 13 for the `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders\` key path would provide direct registry-level detection of this technique.
