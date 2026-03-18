# T1112-28: Modify Registry — Windows HideSCAHealth Group Policy Feature

## Technique Context

T1112 (Modify Registry) involves adversaries making changes to Windows registry to hide system artifacts, maintain persistence, or evade detection mechanisms. The HideSCAHealth registry modification specifically targets the Windows Security Center, disabling or hiding security-related notifications and status indicators from users. This technique is commonly used by malware to prevent users from seeing warnings about disabled security features, allowing threats to operate with reduced visibility. Detection engineers focus on monitoring registry modifications to policy-related keys, particularly those affecting security controls, user interfaces, and system notifications.

## What This Dataset Contains

This dataset captures a registry modification attack that successfully creates the HideSCAHealth registry value. The technique execution shows in Security event 4688:

Process creation chain: `powershell.exe` → `cmd.exe` → `reg.exe` with command line `reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v HideSCAHealth /t REG_DWORD /d 1 /f`

Sysmon captures three distinct process creations (EID 1):
- `whoami.exe` for system discovery (T1033)
- `cmd.exe` executing the registry modification command (T1059.003) 
- `reg.exe` performing the actual registry modification (T1012)

The PowerShell events contain only test framework boilerplate (`Set-StrictMode`, `Set-ExecutionPolicy Bypass`) with no attack-specific script content. All processes execute under NT AUTHORITY\SYSTEM context with exit status 0x0, indicating successful completion. Sysmon also captures process access events (EID 10) showing PowerShell accessing the spawned child processes.

## What This Dataset Does Not Contain

This dataset lacks direct evidence of the registry modification itself - no Sysmon registry events (EID 12/13) are present, likely due to the sysmon-modular configuration not monitoring the specific registry key path. There are no file system events showing temporary files or persistence mechanisms. The dataset also doesn't contain any Windows Defender blocking events, indicating the technique executed without endpoint protection interference. Network events are absent as this is a local registry modification technique.

## Assessment

This dataset provides good process-based detection opportunities through Security 4688 and Sysmon EID 1 events, capturing the complete execution chain from PowerShell to reg.exe. The command-line logging clearly shows the specific registry key and value being modified. However, the absence of direct registry modification telemetry (Sysmon EID 12/13) limits the dataset's value for building comprehensive registry-focused detections. The technique succeeded completely, providing authentic telemetry of a successful attack execution rather than blocked attempts.

## Detection Opportunities Present in This Data

1. **Command-line detection** - Monitor for `reg.exe` execution with "HideSCAHealth" parameter in command line (Security 4688 and Sysmon EID 1)

2. **Process chain analysis** - Detect PowerShell spawning cmd.exe which then spawns reg.exe for registry modification operations

3. **Registry policy modification** - Alert on reg.exe targeting `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer` path

4. **Security control tampering** - Monitor for modifications to Explorer policies that could hide security notifications or status

5. **Living-off-the-land detection** - Flag reg.exe usage with /f (force) parameter combined with policy-related registry paths

6. **Process access correlation** - Combine Sysmon EID 10 process access events with subsequent process creation for enhanced behavioral detection

7. **System context abuse** - Monitor for registry modifications executed under SYSTEM privileges that target user policy settings
