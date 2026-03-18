# T1012-4: Query Registry — Reg query for AlwaysInstallElevated status

## Technique Context

T1012 Query Registry is a fundamental discovery technique where adversaries enumerate Windows registry keys and values to gather system information, discover installed software, identify security configurations, or locate credentials. The specific variant tested here focuses on querying the AlwaysInstallElevated policy settings, which when enabled in both HKCU and HKLM hives, allows standard users to install MSI packages with elevated privileges - making it a valuable privilege escalation vector.

The detection community focuses on monitoring registry enumeration patterns, particularly queries to security-sensitive keys like those related to Windows Installer policies, RunKey persistence locations, installed software lists, and credential storage areas. Modern adversaries routinely perform registry reconnaissance as part of initial system surveys and privilege escalation attempts.

## What This Dataset Contains

The dataset captures a PowerShell-executed registry query targeting AlwaysInstallElevated policy settings across both user and machine hives. The key telemetry includes:

**Process Chain**: PowerShell spawns cmd.exe which executes two reg.exe instances with the command line `"cmd.exe" /c reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated & reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated`

**Registry Query Commands**: Two distinct reg.exe processes query:
- `reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated` (PID 7924)  
- `reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated` (PID 7908)

**Exit Status Indicators**: Both reg.exe processes exit with status 0x1 (Security EID 4689), indicating the registry keys were not found - the expected result on a properly configured system.

**Complete Process Telemetry**: Security EID 4688/4689 events provide full command-line visibility, while Sysmon EID 1 events capture the reg.exe executions with detailed process metadata including hashes (SHA256=411AE446FE37B30C0727888C7FA5E88994A46DAFD41AA5B3B06C9E884549AFDE).

## What This Dataset Does Not Contain

This dataset lacks several detection-relevant data points:

**Registry Access Events**: No Sysmon EID 12/13 events showing actual registry key access or value queries, as the sysmon-modular configuration doesn't include registry monitoring rules for these specific keys.

**Successful Query Results**: Since AlwaysInstallElevated is not configured on this system, we don't see the telemetry that would occur if the policy was present and returned actual values.

**PowerShell Script Content**: The PowerShell channel only contains test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) rather than the actual discovery script that triggered the registry queries.

**Network or File System Artifacts**: No evidence of results being exfiltrated or written to files, though this may be due to the test's limited scope.

## Assessment

This dataset provides solid detection opportunities for T1012 registry discovery, particularly for AlwaysInstallElevated enumeration. The command-line logging in Security EID 4688 events delivers the primary detection value, capturing both the specific registry paths and the technique pattern. The Sysmon process creation events add valuable context with process relationships and file hashes.

The exit code telemetry (0x1) adds an interesting dimension - successful queries would exit with 0x0, allowing detection logic to differentiate between reconnaissance attempts and actual policy discoveries. However, the lack of registry access events means defenders must rely primarily on command-line pattern matching rather than direct registry monitoring.

## Detection Opportunities Present in This Data

1. **Command-line pattern detection** - Security EID 4688 events showing reg.exe queries to `SOFTWARE\Policies\Microsoft\Windows\Installer` paths with AlwaysInstallElevated value names

2. **Process chain analysis** - PowerShell spawning cmd.exe which launches reg.exe processes, indicating scripted reconnaissance activity rather than interactive administrative tasks  

3. **Dual-hive enumeration pattern** - Sequential queries to both HKCU and HKLM versions of the same registry path, a signature behavior of AlwaysInstallElevated privilege escalation checks

4. **Registry tool abuse** - Legitimate reg.exe being used for security policy enumeration, detectable through process creation events with specific command patterns

5. **Exit code correlation** - Failed registry queries (exit status 0x1) may indicate reconnaissance attempts against non-existent security configurations

6. **Batch execution detection** - The cmd.exe command combines both registry queries with "&" operator, showing automated rather than manual execution patterns
