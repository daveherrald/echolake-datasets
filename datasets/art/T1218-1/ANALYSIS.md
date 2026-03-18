# T1218-1: System Binary Proxy Execution — mavinject - Inject DLL into running process

## Technique Context

T1218 System Binary Proxy Execution encompasses using legitimate, signed binaries to proxy execution of malicious code. The mavinject.exe variant (T1218.013) is particularly notable as it's a Microsoft-signed binary designed for Application Virtualization that can inject DLLs into running processes. Attackers leverage mavinject because it bypasses application whitelisting and appears legitimate to security tools. The detection community focuses on monitoring mavinject usage outside of legitimate App-V contexts, unusual command-line patterns, injection into sensitive processes, and the loading of unsigned or suspicious DLLs.

## What This Dataset Contains

The dataset captures a complete mavinject DLL injection attempt with rich telemetry across multiple data sources. Security 4688 events show the full process chain: PowerShell (PID 32260) spawns cmd.exe with command line `"cmd.exe" /c mavinject.exe 1000 /INJECTRUNNING "C:\AtomicRedTeam\atomics\T1218\src\x64\T1218.dll"`, followed by mavinject.exe (PID 32924) with arguments `1000 /INJECTRUNNING "C:\AtomicRedTeam\atomics\T1218\src\x64\T1218.dll"`. 

Sysmon provides complementary coverage with EID 1 ProcessCreate events tagged with `technique_id=T1218,technique_name=Signed Binary Proxy Execution` for mavinject.exe and `technique_id=T1059.003,technique_name=Windows Command Shell` for cmd.exe. Critical evidence appears in Sysmon EID 10 ProcessAccess events showing PowerShell accessing both whoami.exe and cmd.exe with full access rights (0x1FFFFF), indicating process manipulation behavior.

The technique appears to fail - mavinject.exe and cmd.exe both exit with status 0x20057 (131159), suggesting the DLL injection was unsuccessful. However, the attempt generates substantial telemetry including the complete command line showing the target PID (1000) and DLL path.

## What This Dataset Does Not Contain

The dataset lacks evidence of successful DLL injection. There are no Sysmon EID 7 ImageLoad events showing T1218.dll being loaded into the target process (PID 1000), no network connections from an injected process, and no registry modifications or file operations from the malicious DLL. The exit codes indicate failure, likely due to the target process not existing or access restrictions. The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy) rather than the actual attack script content. Additionally, we don't see the creation or staging of the T1218.dll file itself.

## Assessment

This dataset provides excellent coverage for detecting attempted mavinject abuse, even when the technique fails. The combination of Security 4688 command-line logging and Sysmon ProcessCreate/ProcessAccess events creates multiple high-fidelity detection opportunities. The failure scenario is actually valuable for detection engineering as it represents the common case where defensive measures prevent successful execution while still generating attack telemetry. The presence of the full command line with DLL path in Security logs makes this particularly useful for building robust detection rules.

## Detection Opportunities Present in This Data

1. **Mavinject process creation outside App-V context** - Sysmon EID 1 or Security 4688 showing mavinject.exe execution with suspicious command lines containing /INJECTRUNNING parameter and non-standard DLL paths.

2. **Command line pattern matching for DLL injection** - Security 4688 command lines matching `mavinject.exe [PID] /INJECTRUNNING [DLL_PATH]` where DLL_PATH points to non-standard locations like user directories or temp folders.

3. **Process access anomalies from script interpreters** - Sysmon EID 10 showing PowerShell or other script engines accessing processes with full rights (0x1FFFFF), particularly when combined with subsequent mavinject execution.

4. **Parent-child process relationship analysis** - Security 4688 showing mavinject.exe spawned by cmd.exe which was spawned by PowerShell, indicating potential automated attack tooling.

5. **File path indicators in command lines** - Detection of paths containing "AtomicRedTeam", "atomics", or other known red team framework indicators in mavinject command lines.

6. **Process exit code correlation** - Monitoring for mavinject processes exiting with error codes (0x20057) combined with preceding suspicious command lines, indicating blocked injection attempts.
