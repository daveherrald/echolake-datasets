# T1218.005-10: Mshta — Mshta used to Execute PowerShell

## Technique Context

T1218.005 (Mshta) is a defense evasion technique where attackers abuse Microsoft HTML Application Host (mshta.exe) to execute malicious code while bypassing application controls. Mshta.exe is a legitimate Windows utility that executes HTA files containing HTML, JavaScript, or VBScript code. Attackers commonly use this technique because mshta.exe is a signed Microsoft binary that can execute script content from various sources including local files, URLs, or inline code via the "about:" protocol.

This technique is particularly effective for defense evasion because many application whitelisting solutions trust mshta.exe by default, and the executed code appears to originate from a legitimate Windows process. Detection engineers focus on monitoring mshta.exe process creation with suspicious command lines, especially those containing script blocks, URLs, or encoded content. The technique often serves as a first-stage loader that subsequently launches other tools like PowerShell.

## What This Dataset Contains

This dataset captures a complete mshta.exe execution chain that spawns PowerShell. The Security 4688 events show the full process chain: `powershell.exe` → `cmd.exe` → `mshta.exe` → `powershell.exe`. The critical Security event shows mshta.exe launched with the command line: `mshta.exe "about:<hta:application><script language="VBScript">Close(Execute("CreateObject(""Wscript.Shell"").Run%20""powershell.exe%20-nop%20-Command%20Write-Host%20Hello,%20MSHTA!;Start-Sleep%20-Seconds%205"""))&lt;/script>'"`.

Sysmon EID 1 events capture the same process creation chain with additional details including process GUIDs, parent-child relationships, and file hashes. The mshta.exe process (PID 20072) is correctly identified with rule name `technique_id=T1218.005,technique_name=Mshta`, and the spawned PowerShell process (PID 10268) has rule name `technique_id=T1218.005,technique_name=Mshta`.

Sysmon EID 7 events show mshta.exe loading VBScript-related DLLs including `vbscript.dll`, `wshom.ocx` (Windows Script Host Runtime Library), and `scrrun.dll` (Microsoft Script Runtime), which are characteristic of mshta.exe executing VBScript content. The dataset also captures AMSI integration via `amsi.dll` loading in the mshta.exe process.

PowerShell logging shows the actual command execution with EID 4104 script block logging capturing `Write-Host Hello, MSHTA!;Start-Sleep -Seconds 5` and EID 4103 command invocation logging showing the `Write-Host` cmdlet execution.

## What This Dataset Does Not Contain

The dataset contains partial command line corruption in several events, where portions show "The system cannot find the device specified" and "No process in the command subtree has a signal handler" messages, indicating some logging issues during capture. This affects the readability of the mshta.exe command lines but the core technique evidence remains intact.

The dataset doesn't contain any Windows Defender blocking activity despite having real-time protection enabled - this indicates the technique executed successfully without triggering behavioral detection. There are no network connections captured, as this test uses the "about:" protocol for inline script execution rather than fetching remote HTA content.

Missing are any registry modifications, file system artifacts beyond PowerShell profile data, or persistence mechanisms, as this test demonstrates a simple execution technique rather than a complete attack chain.

## Assessment

This dataset provides excellent telemetry for detecting T1218.005 (Mshta). The combination of Security 4688 and Sysmon EID 1 events gives comprehensive process creation visibility with command lines, parent-child relationships, and file hashes. The Sysmon configuration correctly identifies both the mshta.exe execution and its PowerShell child process with appropriate rule tags.

The DLL loading events (Sysmon EID 7) are particularly valuable, showing the characteristic script runtime libraries loaded by mshta.exe when executing VBScript content. The PowerShell logging provides complete visibility into the payload execution. Despite some command line corruption in the logs, all essential detection points are present and clear.

This dataset would be stronger with network connection logs for URL-based HTA scenarios and cleaner command line logging, but it excellently demonstrates the core mshta.exe → PowerShell execution pattern that analysts need to detect.

## Detection Opportunities Present in This Data

1. **Process creation of mshta.exe with script-containing command lines** - Security 4688 and Sysmon EID 1 events showing mshta.exe with "about:" protocol and inline script content

2. **Parent-child process relationship anomalies** - mshta.exe spawning PowerShell with suspicious command line parameters like "-nop -Command"

3. **VBScript/JScript DLL loading patterns in mshta.exe** - Sysmon EID 7 events showing vbscript.dll, wshom.ocx, and scrrun.dll loads indicating active script execution

4. **PowerShell execution originating from mshta.exe parent process** - Process lineage analysis showing PowerShell launched by mshta.exe rather than typical parent processes

5. **AMSI DLL loading in mshta.exe context** - EID 7 showing amsi.dll loading in mshta.exe, indicating script content inspection

6. **Command line obfuscation patterns** - URL encoding (%20 for spaces) and VBScript CreateObject/WScript.Shell patterns in mshta.exe arguments

7. **PowerShell script block execution with mshta.exe in process ancestry** - EID 4104 PowerShell logging correlated with mshta.exe parent process

8. **Rapid process creation sequence** - Temporal correlation of cmd.exe → mshta.exe → powershell.exe creation within seconds
