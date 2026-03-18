# T1112-45: Modify Registry — Enabling Restricted Admin Mode via Command_Prompt

## Technique Context

T1112 (Modify Registry) is a fundamental technique that adversaries use to establish persistence, escalate privileges, evade defenses, or alter system behavior by modifying Windows registry keys. This specific test (T1112-45) focuses on enabling Restricted Admin Mode by setting the `DisableRestrictedAdmin` registry value to 0 in the LSA (Local Security Authority) configuration. Restricted Admin Mode is a Windows feature that prevents credential delegation when using Remote Desktop Protocol (RDP), forcing authentication to occur without sending credentials to the remote system. By enabling this mode, attackers can potentially use Pass-the-Hash techniques more effectively in RDP scenarios, as it prevents credential caching on the target system.

The detection community typically focuses on monitoring registry modifications to security-critical keys, particularly those affecting authentication mechanisms, credential handling, and security policies. The LSA registry path (`HKLM\System\CurrentControlSet\Control\Lsa`) is considered high-value for monitoring as it contains settings that directly impact Windows authentication and security subsystems.

## What This Dataset Contains

This dataset captures a complete execution chain showing PowerShell invoking cmd.exe to run reg.exe for registry modification. The key events include:

**Process Chain:** PowerShell (PID 39532) → cmd.exe (PID 24856) → reg.exe (PID 21256)

**Command Line Evidence (Security 4688):** The full command line shows `"cmd.exe" /c reg add "hklm\system\currentcontrolset\control\lsa" /f /v DisableRestrictedAdmin /t REG_DWORD /d 0`

**Registry Modification (Sysmon 13):** Direct capture of the registry write: `HKLM\System\CurrentControlSet\Control\Lsa\DisableRestrictedAdmin` set to `DWORD (0x00000000)`

**Process Creation Events (Sysmon 1):** All three processes captured with full command lines, hashes, and parent-child relationships

**Process Access Events (Sysmon 10):** PowerShell accessing both whoami.exe and cmd.exe processes with full access rights (0x1FFFFF)

The PowerShell channel contains only test framework boilerplate (`Set-StrictMode`, `Set-ExecutionPolicy Bypass`) with no actual technique-specific PowerShell code captured in script blocks.

## What This Dataset Does Not Contain

The dataset lacks some telemetry that could provide additional detection context. Notably, there are no Sysmon ProcessCreate events for the initial PowerShell processes (PIDs 12576 and 39532) due to the sysmon-modular include-mode filtering that only captures processes matching suspicious patterns. However, Security 4688 events provide complete coverage of all process creations with command-line logging.

The dataset doesn't capture any Windows Defender blocking activity, suggesting this technique executed successfully without endpoint protection interference. There's also no evidence of the actual RDP-related behavior that would follow enabling Restricted Admin Mode, as this test only covers the registry modification portion.

## Assessment

This dataset provides excellent telemetry for detecting registry-based T1112 techniques. The combination of Security 4688 events with full command-line logging and Sysmon 13 registry modification events creates robust detection opportunities. The process chain visibility through both Security and Sysmon channels offers multiple detection points and correlation opportunities.

The registry modification event (Sysmon 13) is particularly valuable as it captures the exact registry path, value name, and data being written. This specificity makes it ideal for high-fidelity detection rules. The Security 4688 events provide excellent coverage of the process execution chain with full command-line arguments, enabling detection of both the specific reg.exe command and the broader pattern of PowerShell→cmd.exe→reg.exe process chains.

## Detection Opportunities Present in This Data

1. **Registry Write Detection:** Monitor Sysmon Event ID 13 for writes to `HKLM\System\CurrentControlSet\Control\Lsa\DisableRestrictedAdmin` with any value, as this key specifically controls Restricted Admin Mode

2. **Command Line Pattern Matching:** Detect Security Event ID 4688 with command lines containing `reg add` operations targeting LSA registry paths (`hklm\system\currentcontrolset\control\lsa`)

3. **Process Chain Analysis:** Alert on PowerShell spawning cmd.exe which subsequently spawns reg.exe, especially when targeting security-critical registry locations

4. **Suspicious Registry Tool Usage:** Monitor reg.exe executions (Sysmon Event ID 1) with command lines modifying authentication-related registry keys

5. **LSA Configuration Changes:** Broadly monitor any registry modifications under `HKLM\System\CurrentControlSet\Control\Lsa\` for unauthorized changes to authentication settings

6. **Process Access Correlation:** Combine Sysmon Event ID 10 (process access) with subsequent registry modifications to identify potential credential access preparation activities
