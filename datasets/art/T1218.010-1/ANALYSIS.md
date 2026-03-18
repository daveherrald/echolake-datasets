# T1218.010-1: Regsvr32 — Regsvr32 local COM scriptlet execution

## Technique Context

T1218.010 (Regsvr32) is a defense evasion technique where attackers abuse the legitimate Windows regsvr32.exe utility to execute malicious code. Regsvr32 is designed to register and unregister COM DLLs and ActiveX controls, but it also supports loading scriptlet files (.sct) that can contain arbitrary JScript or VBScript code. This technique allows attackers to execute code while appearing to use a trusted Microsoft-signed binary, potentially bypassing application whitelisting and other security controls. The detection community focuses on unusual regsvr32 command-line patterns, especially those referencing remote URLs or local scriptlet files, and the subsequent process behaviors and network connections that may result from scriptlet execution.

## What This Dataset Contains

This dataset captures a regsvr32.exe execution using the `/s /u /i:` flags to load a local COM scriptlet file. The key evidence appears in Security 4688 events showing the full process chain: `powershell.exe` → `cmd.exe` → `regsvr32.exe` with command line `C:\Windows\system32\regsvr32.exe /s /u /i:"C:\AtomicRedTeam\atomics\T1218.010\src\RegSvr32.sct" scrobj.dll`. Sysmon event 1 captures the regsvr32 process creation with hash details (SHA256=07F30FEA8D9A2DC7A8095CABD30E869ED741432C4C94629AEF86E728C79348CC). Critically, both processes exit with status 0x5 (ACCESS_DENIED), indicating Windows Defender blocked the execution. Sysmon event 7 shows regsvr32 loading scrobj.dll (the Windows Script Component Runtime) at C:\Windows\System32\scrobj.dll, which is the legitimate DLL that processes .sct scriptlet files. The PowerShell events contain only test framework boilerplate (`Set-StrictMode`, `Set-ExecutionPolicy Bypass`) without any technique-specific script content.

## What This Dataset Does Not Contain

This dataset lacks the actual scriptlet execution and its effects because Windows Defender blocked the technique with ACCESS_DENIED errors. Missing are network connections that might result from successful scriptlet execution, file system changes the script might perform, registry modifications, or any child processes the scriptlet code might spawn. There are no application events showing Defender's specific blocking actions, and no Sysmon events showing file reads of the RegSvr32.sct file itself. The dataset also lacks any DNS queries or network traffic that might result from a successful scriptlet that attempts to download additional payloads or communicate with command and control infrastructure.

## Assessment

This dataset provides excellent telemetry for detecting regsvr32 abuse attempts, even when blocked by endpoint protection. The Security 4688 events with full command-line logging capture the suspicious regsvr32 invocation patterns that are the primary detection opportunity for this technique. The Sysmon process creation and image load events add valuable context including file hashes and the loading of scrobj.dll, which is a strong indicator of scriptlet processing. The exit status codes clearly indicate the blocking action, which is realistic telemetry that defenders encounter when endpoint protection is active. While the dataset doesn't show successful execution artifacts, it demonstrates the detection-relevant command-line patterns and process relationships that remain consistent whether the technique succeeds or fails.

## Detection Opportunities Present in This Data

1. **Regsvr32 suspicious command-line arguments** - Security 4688 and Sysmon 1 events showing regsvr32.exe with `/i:` parameter referencing .sct files or unusual paths outside system directories

2. **Regsvr32 with network-capable arguments** - Command lines containing `/i:` followed by URLs, even if blocked, indicating attempted remote scriptlet loading

3. **Scrobj.dll loading correlation** - Sysmon 7 events showing regsvr32.exe loading scrobj.dll, which only occurs when processing scriptlet files

4. **Process tree analysis** - Unusual parent processes (PowerShell, cmd.exe, Office applications) spawning regsvr32.exe with scriptlet-related parameters

5. **Failed execution patterns** - Process exit codes of 0x5 (ACCESS_DENIED) from regsvr32.exe combined with suspicious command-line arguments, indicating blocked abuse attempts

6. **Regsvr32 process creation from scripts** - Regsvr32.exe spawned by scripting engines (PowerShell, Windows Script Host) rather than interactive user sessions or installer processes
