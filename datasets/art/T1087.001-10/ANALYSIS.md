# T1087.001-10: Local Account — Enumerate logged on users via CMD (Local)

## Technique Context

T1087.001 (Account Discovery: Local Account) involves adversaries enumerating local user accounts on a system to understand available accounts for lateral movement, privilege escalation, or persistence. The `query user` command is a common Windows utility used to display information about user sessions on Terminal Services servers, making it valuable for understanding who is currently logged onto a system. This technique is frequently observed in post-exploitation phases where attackers seek to map the local user landscape before attempting credential harvesting or account manipulation. Detection engineering typically focuses on monitoring process creation events for reconnaissance utilities like `query.exe`, `quser.exe`, `whoami.exe`, and `net.exe` with user enumeration parameters.

## What This Dataset Contains

This dataset captures a successful execution of the `query user` command chain through PowerShell. The telemetry shows:

**Process Chain (Security 4688 events):**
- PowerShell execution: `powershell.exe` (PID 24224)
- Command shell invocation: `"cmd.exe" /c query user` (PID 9204)  
- Query utility execution: `query user` (PID 37532)
- Quser utility execution: `"C:\Windows\system32\quser.exe"` (PID 19180)

**Sysmon Process Creation Events (EID 1):**
- `whoami.exe` execution: `"C:\Windows\system32\whoami.exe"` with RuleName `technique_id=T1033,technique_name=System Owner/User Discovery`
- `cmd.exe` execution: `"cmd.exe" /c query user` with RuleName `technique_id=T1059.003,technique_name=Windows Command Shell`
- `query.exe` execution: `query user` with RuleName `technique_id=T1057,technique_name=Process Discovery`
- `quser.exe` execution: `"C:\Windows\system32\quser.exe"` with RuleName `technique_id=T1033,technique_name=System Owner/User Discovery`

**Process Access Events (Sysmon EID 10):**
PowerShell accessed both `whoami.exe` and `cmd.exe` processes with full access rights (0x1FFFFF), indicating process monitoring behavior.

**Exit Status Indicators:**
Security 4689 events show `quser.exe` and `query.exe` both exited with status 0x1, indicating execution but likely no logged-in users to enumerate on this system configuration.

## What This Dataset Does Not Contain

The dataset lacks the actual command output or results from the user enumeration attempts. While we see successful process execution, the exit code 0x1 from both `quser.exe` and `query.exe` suggests no interactive user sessions were found to enumerate. The PowerShell channel contains only standard test framework boilerplate (`Set-StrictMode`, `Set-ExecutionPolicy Bypass`) without any technique-specific script content. No registry access, file system enumeration, or network-based user discovery methods are present. The Sysmon configuration's include-mode filtering means we may be missing some intermediate process creations that don't match the suspicious patterns.

## Assessment

This dataset provides excellent telemetry for detecting local account enumeration via command-line utilities. The Security 4688 events with command-line logging capture the complete attack chain, while Sysmon EID 1 events provide enhanced context with MITRE ATT&CK technique mappings. The process access events (EID 10) add another detection dimension by showing PowerShell's monitoring of child processes. The combination of multiple data sources creates robust detection opportunities. However, the lack of successful enumeration results limits analysis of post-enumeration behavior patterns. The technique executed cleanly without Windows Defender intervention, providing realistic telemetry for a commonly successful reconnaissance method.

## Detection Opportunities Present in This Data

1. **Command-line enumeration pattern detection** - Monitor Security 4688 events for `cmd.exe` with `/c query user` or similar user enumeration commands
2. **Reconnaissance utility process creation** - Alert on Sysmon EID 1 creation of `query.exe`, `quser.exe`, or `whoami.exe` with parent processes outside normal administrative contexts
3. **PowerShell-spawned enumeration tools** - Detect PowerShell processes creating user discovery utilities through parent-child process relationships
4. **Process access monitoring** - Use Sysmon EID 10 events to identify processes accessing enumeration utilities with full permissions, indicating potential process injection or monitoring
5. **Reconnaissance utility clustering** - Correlate multiple user/system discovery tools (`whoami.exe`, `query.exe`, `quser.exe`) executing within short time windows
6. **Command sequence analysis** - Monitor for the specific execution pattern: PowerShell → cmd.exe → query.exe → quser.exe indicating systematic enumeration
7. **MITRE ATT&CK technique correlation** - Leverage Sysmon rule names to detect combinations of T1033 (System Owner/User Discovery) and T1057 (Process Discovery) techniques
