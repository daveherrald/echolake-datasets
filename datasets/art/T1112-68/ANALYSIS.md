# T1112-68: Modify Registry — Set-Up Proxy Server

## Technique Context

T1112 (Modify Registry) is a foundational technique where adversaries alter Windows registry values to achieve defense evasion, persistence, privilege escalation, or other objectives. The detection community focuses heavily on monitoring registry modifications to high-value keys like Run keys, security settings, and system configurations. This specific test simulates setting up a proxy server configuration through registry modification - a technique commonly used by malware to redirect network traffic through attacker-controlled infrastructure for data exfiltration, command and control, or to bypass network security controls. The proxy configuration is stored in `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ProxyServer`, which affects how the user's applications connect to the internet.

## What This Dataset Contains

This dataset captures a successful proxy server configuration via registry modification. The attack chain begins with PowerShell execution (process ID 20740) which spawns `cmd.exe` with the command line `"cmd.exe" /c reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer /t REG_SZ /d "proxy.atomic-test.com:8080" /f`. The `cmd.exe` process (PID 20092) then executes `reg.exe` with arguments `reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer /t REG_SZ /d "proxy.atomic-test.com:8080" /f`.

The critical registry modification is captured in Sysmon EID 13: `Registry value set` showing `TargetObject: HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ProxyServer` with `Details: proxy.atomic-test.com:8080`. Note that the modification occurs under `HKU\.DEFAULT` (the default user profile) rather than a specific user hive, since the test runs as SYSTEM.

Security event 4688 provides complete command-line visibility for the process chain: PowerShell → cmd.exe → reg.exe. The dataset also includes Sysmon EID 1 (Process Create) events for both the `cmd.exe` and `reg.exe` processes, along with Sysmon EID 10 (Process Access) events showing PowerShell accessing both child processes.

## What This Dataset Does Not Contain

The dataset does not capture any network connections resulting from the proxy configuration, as this test only sets the registry value without actually using it. There are no Sysmon EID 3 (Network Connection) events showing traffic being routed through the configured proxy server. The test also doesn't include any subsequent processes attempting to use the proxy configuration or any browser/application startup that would leverage the new setting.

Since the test runs as SYSTEM and modifies the default user profile registry, it doesn't demonstrate the typical user-context scenario where malware would modify the current user's proxy settings. The PowerShell events contain only framework boilerplate (`Set-StrictMode`, `Set-ExecutionPolicy`) rather than the actual test execution commands.

## Assessment

This dataset provides excellent coverage for detecting registry-based proxy configuration attacks. The combination of Sysmon EID 13 (registry modification), Security EID 4688 (process creation with command lines), and Sysmon EID 1 (process creation with full context) gives multiple detection opportunities. The command-line logging captures the exact `reg.exe` arguments, making it straightforward to identify proxy configuration attempts. The registry modification event provides the specific target key and value, enabling precise detection of this persistence/evasion technique. This is a high-quality dataset for building detections around malicious proxy configuration.

## Detection Opportunities Present in This Data

1. Registry modification to Internet Settings proxy configuration (`Sysmon EID 13` targeting `*\Internet Settings\ProxyServer`)
2. Command-line execution of `reg.exe add` with proxy-related arguments (`Security EID 4688` or `Sysmon EID 1` with CommandLine containing `ProxyServer`)
3. Process chain analysis of PowerShell spawning cmd.exe spawning reg.exe for registry modification (`Sysmon EID 1` parent-child relationships)
4. Registry tool execution with Internet Settings modification (`Sysmon EID 1` where Image is `*\reg.exe` and CommandLine contains `Internet Settings`)
5. Suspicious proxy server hostnames in registry values (`Sysmon EID 13` Details field analysis for non-corporate proxy servers)
6. SYSTEM context proxy configuration which is unusual for legitimate administrative tasks (`Sysmon EID 13` with User `NT AUTHORITY\SYSTEM`)
