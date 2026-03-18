# T1003.002-5: Security Account Manager — dump volume shadow copy hives with certutil

## Technique Context

T1003.002 targets the Security Account Manager (SAM) database, which stores local Windows account credentials including password hashes. The SAM is a critical target for credential harvesting as it contains NTLM hashes for all local users. This specific test demonstrates using certutil.exe as a Living off the Land Binary (LOLBin) to dump SAM hives from Volume Shadow Copy snapshots. Volume Shadow Copy access is a common persistence and privilege escalation technique because it allows reading files that are normally locked by the operating system. The detection community focuses heavily on certutil abuse due to its dual-use nature (legitimate certificate operations vs. credential dumping), command-line patterns indicating volume shadow copy access, and the specific file paths associated with credential stores.

## What This Dataset Contains

This dataset captures a comprehensive attempt to dump SAM hives from multiple Volume Shadow Copy snapshots using certutil. The Security channel shows the complete process chain with command-line logging: PowerShell (PID 6992) spawning `cmd.exe /c for /L %a in (1,1,10) do @(certutil -f -v -encodehex "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy%a\Windows\System32\config\SAM" %temp%\SAMvss%a 2 >nul 2>&1) & dir /B %temp%\SAMvss*`, which then creates ten certutil processes attempting to access shadow copies 1-10. Each certutil execution shows the distinctive command line: `certutil -f -v -encodehex "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy[1-10]\Windows\System32\config\SAM" C:\Windows\TEMP\SAMvss[1-10] 2`.

The Sysmon data provides rich process creation events (EID 1) for all certutil instances with full hashes and parent process relationships. Notably, all certutil processes exit with error code `0x80070003` (ERROR_PATH_NOT_FOUND) in Security EID 4689 events, indicating the shadow copy paths don't exist on this system. The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) with no technique-specific content. Sysmon also captures the GLOBALROOT device path syntax, which is a key indicator of volume shadow copy access attempts.

## What This Dataset Does Not Contain

This dataset represents a failed execution where no Volume Shadow Copy snapshots existed for the attack to leverage. There are no successful file creation events for the SAM dumps, no process access events targeting the SAM database, and no network activity. The lack of Sysmon ProcessCreate events for the parent PowerShell processes is expected due to the include-mode filtering that only captures known-suspicious processes like certutil. The absence of Windows Defender blocking events suggests the technique attempt proceeded but failed due to environmental constraints rather than security controls. There are no registry access events or privilege escalation indicators beyond the initial process creation chain.

## Assessment

This dataset provides excellent detection value despite the failed execution. The telemetry captures the complete attack pattern including the distinctive for-loop command structure, GLOBALROOT device path syntax, and multiple certutil executions with volume shadow copy targeting. The Security channel's command-line logging is particularly valuable, showing both the batch loop construct and individual certutil invocations. The combination of process creation events (Security EID 4688, Sysmon EID 1) and process termination events (Security EID 4689) with error codes provides clear evidence of the attempt and its failure. This represents a realistic scenario where attackers may attempt credential dumping on systems without existing shadow copies.

## Detection Opportunities Present in This Data

1. **Certutil Volume Shadow Copy Access**: Detect certutil.exe with command lines containing "GLOBALROOT\Device\HarddiskVolumeShadowCopy" and credential store paths like "\Windows\System32\config\SAM"

2. **Batch Loop Credential Dumping**: Identify cmd.exe processes with for-loops iterating through HarddiskVolumeShadowCopy device paths combined with certutil encoding operations

3. **Multiple Certutil Process Spawning**: Alert on rapid creation of multiple certutil.exe processes with similar command line patterns within a short time window

4. **GLOBALROOT Device Path Access**: Monitor for any process attempting to access the \\?\GLOBALROOT\Device\ namespace, particularly when combined with system credential file paths

5. **Certutil Encodehex with System Files**: Detect certutil.exe using -encodehex parameter targeting Windows system configuration files (SAM, SYSTEM, SECURITY)

6. **Process Exit Code Analysis**: Correlate certutil executions with ERROR_PATH_NOT_FOUND (0x80070003) exit codes as potential failed credential dumping attempts

7. **Parent-Child Process Relationship**: Monitor PowerShell or cmd.exe spawning multiple certutil processes with volume shadow copy access patterns
