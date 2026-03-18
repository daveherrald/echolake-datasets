# T1204.002-11: Malicious File — Mirror Blast Emulation

## Technique Context

T1204.002 (User Execution: Malicious File) covers scenarios where attackers rely on users to open malicious documents or executable files that trigger code execution. The Mirror Blast campaign, attributed to threat actors including TA505, delivered malicious Excel files (.xlsm) with embedded VBA macros to targeted organizations. The attack chain typically involves a phishing email delivering an Excel document, which uses a macro-enabled format and disables Excel's macro warnings via a registry modification before opening the file. Detection engineers focus on Office application child process spawning, VBA warning registry modifications, and the behavioral patterns of macro-enabled documents opening in enterprise environments.

## What This Dataset Contains

This dataset captures the pre-execution attack setup phase of the Mirror Blast emulation. The key command is visible in Security EID 4688 and Sysmon EID 1, where a PowerShell process (PID 0x15f0) is created with the command:

`"powershell.exe" & {Cd "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\" New-ItemProperty -Path Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office\16.0\Excel\Security -Name "VBAWarnings" -Value "1" -PropertyType DWORD -Force | Out-Null & '.\Excel 2016.lnk' "C:\AtomicRedTeam\atomics\T1204.002\bin\mirrorblast_emulation.xlsm"}`

This command does two things: first, it sets the `VBAWarnings` registry value to `1` (disable macro warnings) under `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office\16.0\Excel\Security`; second, it attempts to open the malicious XLSM file via the `Excel 2016.lnk` shortcut. The registry modification is the security bypass — without it, Excel would prompt the user before executing macros.

Sysmon EID 1 confirms the `reg.exe` cleanup step during test teardown: `"C:\Windows\system32\reg.exe" delete HKCU\SOFTWARE\Microsoft\Office\16.0\Excel\Security /v VBAWarnings /f`, tagged by Sysmon as `technique_id=T1012,technique_name=Query Registry`. The PowerShell EID 4104 cleanup block `& {reg delete "HKCU\SOFTWARE\Microsoft\Office\16.0\Excel\Security" /v "VBAWarnings" /f}` is also captured in the script block log.

The Security channel records 5 EID 4688 events: whoami.exe (twice), PowerShell (twice — the attack script and the cleanup), and reg.exe (cleanup). The Sysmon channel provides 39 events: 25 EID 7, 5 EID 1, 5 EID 10, 3 EID 17, and 1 EID 11. The EID 7 DLL loads include Windows Defender components (MpOAV.dll, MpClient.dll) loading into the PowerShell processes, indicating that even with Defender nominally disabled, some Defender infrastructure remains loaded.

The PowerShell channel records 112 events (111 EID 4104, 1 EID 4103), predominantly test framework boilerplate.

## What This Dataset Does Not Contain

The actual Excel process execution (`EXCEL.EXE`) and any macro execution artifacts are absent. Despite Defender being disabled, Office was not present on the test system (`ACME-WS06`) or the Excel shortcut invocation failed — no EXCEL.EXE process creation appears in either channel. This means the "malicious document runs macro" phase of the Mirror Blast chain is not represented.

If Excel had launched and executed the macro, you would expect additional EID 4688 / EID 1 events showing EXCEL.EXE spawning child processes, EID 7 showing Office DLL loads, potentially EID 3 network connections from the macro's C2 callback, and EID 13 registry modifications beyond the VBAWarnings key. None of these are present.

In the defended variant, Defender also blocked the Excel execution, so both datasets capture the same pre-execution phase without the macro running. The registry modification artifact (VBAWarnings = 1) is the most forensically valuable element in both.

## Assessment

Even without the full macro execution chain, this dataset contains one of the most actionable detection artifacts in the T1204.002 category: the explicit registry modification disabling VBA macro security warnings (`HKCU\SOFTWARE\Microsoft\Office\16.0\Excel\Security\VBAWarnings = 1`). This modification precedes every macro-based attack and is highly specific — legitimate software rarely sets this value programmatically, and doing so from a PowerShell process rather than an Office installer is extremely suspicious.

The Security EID 4688 command line is also highly specific: it navigates to the Start Menu Programs directory and invokes a `.lnk` file with a `.xlsm` file as an argument, a pattern consistent with social engineering attacks that disguise macro-enabled documents as legitimate shortcuts.

## Detection Opportunities Present in This Data

- **Security EID 4688 / Sysmon EID 1**: PowerShell executing `New-ItemProperty` targeting `HKCU\SOFTWARE\Microsoft\Office\16.0\Excel\Security` with `VBAWarnings = 1` — this registry key modification is a pre-attack security bypass and should be treated as a high-priority alert
- **Security EID 4688**: The command pattern of navigating to `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\` from PowerShell and invoking a `.lnk` file with an `.xlsm` argument is not normal Office usage behavior
- **Sysmon EID 1 / EID 4688**: `reg.exe` invoked from PowerShell to delete the `VBAWarnings` registry key during cleanup — the presence of the cleanup operation itself implies the modification was made earlier
- **PowerShell EID 4104**: Script blocks containing the `Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office` path combined with `VBAWarnings` are a specific, high-fidelity Mirror Blast indicator
- **File presence**: `C:\AtomicRedTeam\atomics\T1204.002\bin\mirrorblast_emulation.xlsm` would be present on disk before the attack — monitoring for `.xlsm` or macro-enabled Office format files appearing in non-standard locations is a useful pre-execution detection
- **Sysmon EID 7**: MpOAV.dll and MpClient.dll loading into PowerShell processes indicates real-time protection engagement — their presence alongside VBAWarnings manipulation suggests the endpoint protection was scrutinizing but ultimately not blocking the operation
