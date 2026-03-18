# T1218.011-8: Rundll32 — Execution of HTA and VBS Files using Rundll32 and URL.dll

## Technique Context

T1218.011 (Rundll32) is a defense evasion technique where attackers abuse the legitimate Windows rundll32.exe utility to proxy execution of malicious code. This technique is particularly effective because rundll32.exe is a trusted system binary that's commonly used for legitimate purposes, making malicious activity harder to detect. In this specific test case, attackers use rundll32.exe with URL.dll exports (OpenURL and FileProtocolHandler) to execute HTA (HTML Application) and VBS (Visual Basic Script) files, effectively bypassing application whitelisting controls.

The detection community focuses on monitoring rundll32.exe for unusual command-line patterns, particularly when it's used to execute files with suspicious extensions or from unusual locations. Key indicators include rundll32.exe loading URL.dll with OpenURL or FileProtocolHandler exports, execution of script files (.hta, .vbs, .js), and child process spawning from rundll32.exe that indicates successful code execution.

## What This Dataset Contains

This dataset captures a complete execution chain demonstrating the rundll32/URL.dll technique. The attack begins with PowerShell spawning cmd.exe with the command line: `"cmd.exe" /c rundll32.exe url.dll,OpenURL "C:\AtomicRedTeam\atomics\T1218.011\src\index.hta" & rundll32.exe URL.dll,FileProtocolHandler "C:\AtomicRedTeam\atomics\T1218.011\src\akteullen.vbs"`.

Security Event ID 4688 captures two rundll32.exe process creations with the distinctive command lines:
- `rundll32.exe url.dll,OpenURL "C:\AtomicRedTeam\atomics\T1218.011\src\index.hta"`
- `rundll32.exe URL.dll,FileProtocolHandler "C:\AtomicRedTeam\atomics\T1218.011\src\akteullen.vbs"`

Sysmon Event ID 1 provides additional process creation details, showing rundll32.exe processes (PIDs 12164 and 24316) with the technique rule name "technique_id=T1218.011,technique_name=rundll32.exe". The second rundll32.exe instance successfully spawns wscript.exe with command line `"C:\Windows\System32\WScript.exe" "C:\AtomicRedTeam\atomics\T1218.011\src\akteullen.vbs"`, demonstrating successful VBS execution.

Sysmon Event ID 7 shows rundll32.exe loading urlmon.dll, which is expected behavior for URL.dll exports. The wscript.exe process loads vbscript.dll and amsi.dll, indicating VBS script processing and AMSI inspection.

## What This Dataset Does Not Contain

The dataset doesn't capture the HTA file execution details - while we see rundll32.exe called with the OpenURL export for the HTA file, there's no evidence of mshta.exe spawning or browser processes launching to handle the HTA content. This suggests the HTA execution may have failed or was blocked by Windows Defender.

Missing are any network connections that might result from script execution, file system modifications beyond PowerShell startup profiles, and registry changes that could indicate persistence mechanisms. The Sysmon configuration's include-mode filtering means we only see processes matching suspicious patterns, so any benign child processes spawned by the scripts wouldn't be captured.

The PowerShell channel contains only standard test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) without any technique-specific script content, indicating the test used external script files rather than inline PowerShell commands.

## Assessment

This dataset provides excellent coverage for detecting T1218.011 abuse via URL.dll exports. The combination of Security 4688 events with full command-line logging and Sysmon 1 events gives comprehensive visibility into the rundll32.exe execution pattern. The successful VBS execution chain (rundll32 → wscript.exe → vbscript.dll loading) demonstrates a complete attack path that detection rules can target.

The process lineage is clearly captured: PowerShell → cmd.exe → rundll32.exe → wscript.exe, providing multiple detection points. The specific DLL exports (url.dll,OpenURL and URL.dll,FileProtocolHandler) are visible in command lines, enabling precise signature-based detection. This dataset would be highly valuable for testing detection rules focused on rundll32.exe abuse patterns.

## Detection Opportunities Present in This Data

1. **Rundll32.exe with URL.dll exports** - Monitor for rundll32.exe command lines containing "url.dll,OpenURL" or "URL.dll,FileProtocolHandler" patterns
2. **Rundll32.exe executing script files** - Detect rundll32.exe command lines referencing files with .hta, .vbs, .js, or other script extensions
3. **Rundll32.exe spawning script interpreters** - Alert on rundll32.exe parent processes creating wscript.exe, cscript.exe, or mshta.exe child processes
4. **Script execution from temp/atomic directories** - Monitor for script interpreters executing files from suspicious paths like AtomicRedTeam directories
5. **Cmd.exe with compound rundll32 commands** - Detect cmd.exe /c command lines containing multiple rundll32.exe invocations with ampersand separators
6. **Urlmon.dll loading by rundll32** - Track rundll32.exe processes loading urlmon.dll, which may indicate URL handling abuse
7. **VBScript.dll loading in wscript context** - Monitor for vbscript.dll loads in processes spawned by rundll32.exe
8. **AMSI.dll loading in script contexts** - Detect AMSI inspection of scripts executed through rundll32.exe proxy execution
9. **Process access events from PowerShell to rundll32** - Alert on PowerShell processes accessing rundll32.exe processes with full access rights (0x1FFFFF)
