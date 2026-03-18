# T1112-59: Modify Registry — Modify Internet Zone Protocol Defaults in Current User Registry - cmd

## Technique Context

T1112 (Modify Registry) is a foundational technique where adversaries alter Windows registry entries to achieve persistence, disable security features, or modify system behavior. Internet Zone Protocol Defaults manipulation specifically targets Internet Explorer's security model by modifying how different protocols (HTTP/HTTPS) are handled within IE's security zones. The registry path `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\ProtocolDefaults` controls which security zone protocols default to, with zone 0 being the most permissive (My Computer zone). Attackers modify these settings to bypass security restrictions, enable script execution, or facilitate drive-by download attacks. Detection engineers focus on monitoring registry modifications to IE security settings, particularly when performed by unexpected processes or with suspicious timing patterns.

## What This Dataset Contains

This dataset captures a successful execution of registry modifications targeting IE security zones. The core technique manifests through a clear process chain: PowerShell (PID 9824) → cmd.exe (PID 40372) → two reg.exe processes (PIDs 10408, 10852). Security event 4688 shows cmd.exe executing with the complete command line: `"cmd.exe" /c reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\ProtocolDefaults" /v http /t REG_DWORD /d 0 /F & reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\ProtocolDefaults" /v https /t REG_DWORD /d 0 /F`. Two separate Sysmon EID 1 events capture the individual reg.exe executions: the first adding the HTTP protocol mapping (`reg add...http...`) and the second adding HTTPS (`reg add...https...`). Both registry operations set the protocol values to 0, mapping them to the My Computer zone (the most permissive security zone). The dataset includes full process creation and termination events (Security 4688/4689) for all components, demonstrating successful completion with exit status 0x0.

## What This Dataset Does Not Contain

The dataset lacks Sysmon EID 13 (Registry Value Set) events that would show the actual registry modifications being written. This absence indicates either the sysmon-modular configuration doesn't monitor this specific registry path, or the events were filtered out. The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) without any script block logging of the actual technique execution, suggesting the registry commands were executed through a different code path. There are no Windows Defender alerts or blocking actions despite the security-relevant nature of modifying IE zone settings, indicating the technique succeeded without AV intervention. The dataset also lacks any Registry audit events from the Security channel, which would require specific object access auditing to be configured for registry modifications.

## Assessment

This dataset provides excellent coverage for process-based detection of registry zone manipulation through its complete process genealogy and command-line capture. The Security 4688 events with command-line logging deliver the core evidence needed to identify this technique, while Sysmon EID 1 events provide additional process creation details and hashes. However, the lack of registry modification events (Sysmon EID 13) limits visibility into the actual persistence mechanism being established. For comprehensive detection of T1112, this data source combination captures the execution vector but misses the registry modification artifacts that would confirm successful persistence establishment. The dataset excels at identifying the attack attempt but falls short of proving the attack's success from a persistence perspective.

## Detection Opportunities Present in This Data

1. Command-line analysis detecting reg.exe operations targeting Internet Explorer security zone registry paths (`HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\ProtocolDefaults`)

2. Process chain analysis identifying PowerShell → cmd.exe → reg.exe execution patterns, particularly when reg.exe is spawned by non-administrative tools

3. Registry tool invocation monitoring when reg.exe executes with "add" operations against IE security configuration paths

4. Batch command detection analyzing cmd.exe executions containing multiple registry operations chained with "&" operators targeting browser security settings

5. Zone mapping abuse detection by monitoring reg.exe operations that set protocol values to "0" (My Computer zone), especially for HTTP/HTTPS protocols

6. Parent-child process relationship monitoring for reg.exe processes spawned by scripting interpreters (PowerShell, cmd.exe) with security-relevant registry targets

7. Command-line pattern matching for registry operations containing "ZoneMap", "ProtocolDefaults", and zone value assignments in a single execution
