# T1112-3: Modify Registry — Modify registry to store logon credentials

## Technique Context

T1112 (Modify Registry) is a fundamental defense evasion and persistence technique where attackers modify Windows registry keys to alter system behavior, disable security features, or establish persistence. This specific test implements a credential harvesting variant by enabling WDigest authentication plaintext credential storage. When the `HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential` value is set to 1, Windows stores plaintext passwords in LSASS memory for future authentication attempts. This technique has been widely used by threat actors since its public disclosure, particularly in post-exploitation scenarios where attackers have already gained administrative access and want to harvest credentials for lateral movement. The detection community focuses on monitoring registry modifications to security-sensitive keys, especially those affecting authentication providers and credential storage mechanisms.

## What This Dataset Contains

This dataset captures a successful registry modification attack targeting WDigest credential storage. The attack begins with PowerShell execution (PID 20948) and proceeds through the following command chain: `powershell.exe` → `cmd.exe /c reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f` → `reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f`. 

The key evidence includes Security event 4688 showing the cmd.exe creation with the full command line revealing the registry modification intent, followed by Security event 4688 for reg.exe with the complete registry command. Most importantly, Sysmon event 13 captures the actual registry value being set: `TargetObject: HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential` with `Details: DWORD (0x00000001)`. The dataset also contains Sysmon events 1 for process creation of whoami.exe, cmd.exe, and reg.exe, along with multiple PowerShell image loads and process access events.

## What This Dataset Does Not Contain

The dataset lacks certain complementary events that would strengthen detection coverage. There are no registry key creation events (Sysmon EID 12) showing when the WDigest key structure is established, only the value modification (EID 13). The PowerShell channel contains only test framework boilerplate (Set-ExecutionPolicy Bypass) rather than the actual PowerShell commands that initiated the attack, suggesting the malicious commands may have been executed through other means or the logging didn't capture the script block content. Additionally, while the technique successfully modifies the registry, there's no evidence of subsequent credential harvesting attempts or LSASS memory access that would demonstrate exploitation of the weakened security posture.

## Assessment

This dataset provides excellent coverage of the core T1112 technique execution, particularly for registry-based credential harvesting attacks. The Security channel's command-line logging captures the attack intent clearly, while Sysmon's registry monitoring (EID 13) provides the definitive evidence of the malicious modification. The process creation events create a complete attack timeline from PowerShell through reg.exe execution. The combination of command-line visibility and registry monitoring makes this dataset particularly valuable for developing robust detections that can identify both the attack method (command-line patterns) and the attack outcome (registry modifications). The only limitation is the absence of PowerShell script content, but the process-level telemetry compensates adequately for detection engineering purposes.

## Detection Opportunities Present in This Data

1. **Registry Value Modification Detection** - Sysmon EID 13 showing `TargetObject` containing `WDigest\UseLogonCredential` with `Details: DWORD (0x00000001)` indicates credential harvesting preparation

2. **Command Line Pattern Detection** - Security EID 4688 with `CommandLine` containing "reg add" + "WDigest" + "UseLogonCredential" patterns indicating registry-based credential access preparation

3. **Process Chain Analysis** - Detection of PowerShell spawning cmd.exe which spawns reg.exe, particularly when targeting security-related registry paths

4. **WDigest Registry Key Monitoring** - Any modifications to `HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest` regardless of the specific value or method used

5. **Administrative Tool Abuse** - reg.exe execution with SYSTEM privileges modifying authentication provider settings, especially when spawned from scripting engines

6. **Credential Access Preparation** - Correlation of registry modifications that weaken credential protection (WDigest enablement) with subsequent suspicious LSASS access attempts
