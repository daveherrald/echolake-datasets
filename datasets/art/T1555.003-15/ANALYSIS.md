# T1555.003-15: Credentials from Web Browsers — WebBrowserPassView - Credentials from Browser

## Technique Context

MITRE ATT&CK T1555.003 (Credentials from Web Browsers) includes use of third-party credential recovery utilities. WebBrowserPassView is a GUI and command-line utility by NirSoft that decrypts and displays saved passwords from all major browsers including Chrome, Firefox, Internet Explorer, Edge, and Opera. It is a legitimate password recovery tool frequently abused by threat actors and included in many offensive toolkits. Defender flags WebBrowserPassView as a Potentially Unwanted Application (PUA) due to its dual-use nature.

## What This Dataset Contains

**Command executed (Security 4688 and Sysmon EID=1):**
```
"powershell.exe" & {Start-Process "C:\AtomicRedTeam\atomics\T1555.003\bin\WebBrowserPassView.exe"
Start-Sleep -Second 4
Stop-Process -Name "WebBrowserPassView"}
```

**PowerShell 4104 script blocks:**
- Both the `& {Start-Process ...}` form and the bare `{Start-Process ...}` form captured verbatim, exposing the binary path and the 4-second runtime window followed by force-termination.

**Sysmon EID=1 (Process Create):**
- `whoami.exe` (T1033) and the child `powershell.exe` (T1059.001) that runs the Start-Process block.
- **Notably absent:** No EID=1 for `WebBrowserPassView.exe` itself. The Sysmon include-mode ProcessCreate filter does not match the binary name, and Defender likely blocked the process before it could fully create — the Start-Process command was issued but the binary execution was intercepted.

**Sysmon EID=3 (Network Connection):**
- Outbound connection from `MpDefenderCoreService.exe` to `52.123.249.35:443` — Microsoft Defender cloud protection service performing a reputation lookup on the WebBrowserPassView binary. This is a reliable indicator of Defender engaging with a suspicious binary at launch time.

**Security exit codes:**
- All PowerShell processes exited `0x0`. The `Stop-Process` in the script block would silently succeed or fail regardless of whether the target process ran — the test framework completed without error.

## What This Dataset Does Not Contain (and Why)

**WebBrowserPassView process creation:** Windows Defender blocks WebBrowserPassView.exe at launch as PUA or malware. The binary never fully started as a process — Defender's behavior monitoring intercepted it before the process create completed to a point where Sysmon would fire an EID=1. The Security 4688 also does not show WebBrowserPassView.exe because Defender terminated it before the process creation audit event was generated (or the process simply did not start).

**Credential access:** No browser credential files were accessed. Defender blocked the tool before it could query any browser stores.

**Sysmon EID=1 on the attacker binary:** This is a known gap with Sysmon include-mode filtering combined with AV blocking — the process never reached the state where Sysmon's driver hooks would fire an EID=1. Security 4688 with command-line auditing would catch this if the process were allowed to run, but Defender's preemptive block prevents even the 4688.

## Assessment

Windows Defender blocked WebBrowserPassView before execution. The clearest artifact is the Defender cloud connection in Sysmon EID=3 from `MpDefenderCoreService.exe` — this is the defender response to a suspicious binary being launched. The PowerShell 4104 script blocks expose the binary path and the attempt intent. The absence of the tool itself in any process telemetry is the blocked-execution pattern: script-level evidence of intent without process-level evidence of execution.

## Detection Opportunities Present in This Data

- **PowerShell 4104** contains `Start-Process "...WebBrowserPassView.exe"` — the binary name is a known-bad indicator and should alert immediately.
- **Security 4688** captures the PowerShell command with `WebBrowserPassView` in the command line — detectable without script block logging.
- **Sysmon EID=3 from `MpDefenderCoreService.exe`** to Microsoft cloud IPs (`52.123.249.35`) immediately following a suspicious `Start-Process` call is a behavioral indicator of Defender engaging with a newly-launched binary.
- Absence of an expected process (WebBrowserPassView.exe) in process telemetry after a `Start-Process` invocation can indicate AV blocking — use process creation + termination correlation to detect silent blocks.
- The `Start-Process ... ; Start-Sleep -Second 4 ; Stop-Process` pattern is indicative of automated test framework execution rather than interactive use; in real attacks, the tool would run interactively or with `/stext` flags for output.
- File path `C:\AtomicRedTeam\atomics\T1555.003\bin\WebBrowserPassView.exe` is an ART-specific artifact; in real attacks the binary would be staged elsewhere.
