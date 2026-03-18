# T1112-51: Modify Registry — Disable Win Defender Notification

## Technique Context

T1112 (Modify Registry) is a fundamental technique used by adversaries to alter Windows registry values for defense evasion or persistence. This specific test targets Windows Defender Security Center notifications by creating a policy registry entry to disable user notifications about security events. Attackers commonly disable security notifications to reduce the likelihood of users noticing malicious activity or security tool alerts.

The detection community focuses heavily on registry modifications to security-related keys, particularly those affecting Windows Defender, UAC, logging, and other defensive mechanisms. Registry modifications are high-fidelity indicators when targeting security controls, making this technique valuable for both red teams demonstrating impact and blue teams validating detection coverage.

## What This Dataset Contains

The dataset captures a successful registry modification executed through PowerShell spawning cmd.exe with reg.exe. The key telemetry shows:

**Process Chain (Security 4688):**
- PowerShell → cmd.exe: `"cmd.exe" /c reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" /v "DisableNotifications" /t REG_DWORD /d 1 /f`
- cmd.exe → reg.exe: `reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" /v "DisableNotifications" /t REG_DWORD /d 1 /f`

**Registry Modification (Sysmon EID 13):**
- TargetObject: `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications\DisableNotifications`
- Details: `DWORD (0x00000001)`
- Process: `C:\Windows\system32\reg.exe`

**Sysmon Process Creation (EID 1):**
- cmd.exe creation with full command line visible
- reg.exe creation with registry modification command
- whoami.exe execution (likely test framework validation)

The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) with no attack-specific PowerShell script blocks captured.

## What This Dataset Does Not Contain

This dataset lacks PowerShell script block logging of the actual attack command, suggesting the registry modification was executed through direct process spawning rather than PowerShell cmdlets. The attack succeeded completely (exit code 0x0), so there are no Windows Defender blocking events or access denied conditions.

Notably absent are:
- PowerShell script blocks showing registry modification cmdlets
- Alternative registry modification methods (direct Win32 API calls)
- Windows Defender real-time protection alerts (the modification targets notification settings, not core protection)
- Follow-on evidence of the notification suppression taking effect

## Assessment

This dataset provides excellent coverage for detecting registry-based defense evasion targeting Windows Defender notifications. The combination of Security event 4688 (command-line logging) and Sysmon event 13 (registry modification) creates multiple detection opportunities with high fidelity. The process chain visibility from PowerShell through reg.exe execution is particularly valuable for understanding attack context.

The registry target path and value modification are unambiguous indicators of malicious intent - legitimate administrative tools rarely disable security notifications through policy registry entries. This makes the dataset highly suitable for developing low false-positive detection rules.

## Detection Opportunities Present in This Data

1. **Registry modification to Windows Defender notification settings** - Sysmon EID 13 with TargetObject matching `*Windows Defender Security Center\Notifications*` and value names like `DisableNotifications`

2. **Suspicious reg.exe command line patterns** - Security EID 4688 or Sysmon EID 1 with CommandLine containing `reg add` targeting Windows Defender policy paths

3. **Process chain analysis** - PowerShell spawning cmd.exe spawning reg.exe with security-related registry modifications

4. **Defense evasion registry keys** - Any registry SET operations to `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center` paths

5. **Command-line pattern matching** - Detection of `/v "DisableNotifications"` or similar notification disabling parameters in reg.exe executions

6. **Cross-correlation opportunities** - Registry modifications immediately followed by security tool behavior changes or reduced logging volume
