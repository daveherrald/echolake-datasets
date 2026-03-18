# T1110.001-8: Password Guessing — ESXi - Brute Force Until Account Lockout

## Technique Context

T1110.001 Password Guessing is a credential access technique where adversaries attempt to gain unauthorized access by systematically trying different passwords against known user accounts. ESXi brute force attacks specifically target VMware vSphere infrastructure, which is critical in enterprise environments. Attackers often use automated tools to cycle through common passwords or password lists against ESXi management interfaces, potentially leading to hypervisor compromise and lateral movement across virtualized environments. The detection community focuses on identifying patterns of repeated authentication failures, unusual login timing, and tools commonly used for password spraying attacks like plink.exe for SSH connections.

## What This Dataset Contains

This dataset captures a PowerShell-driven ESXi brute force simulation that executes 5 password guessing attempts against "atomic.local" using plink.exe. The key evidence includes:

**Primary Attack Process**: Security EID 4688 shows the main PowerShell process (PID 0x4cec) created with the full command line: `"powershell.exe" & {$lockout_threshold = [int]\"5\"; for ($var = 1; $var -le $lockout_threshold; $var++) { C:\AtomicRedTeam\atomics\..\ExternalPayloads\plink.exe -ssh \"atomic.local\" -l root -pw f0b443ae-9565-11ee-b9d1-0242ac120002 }}`

**PowerShell Script Block Evidence**: PowerShell EID 4104 events capture the actual script blocks including the loop structure and hardcoded credentials: `{$lockout_threshold = [int]"5"; for ($var = 1; $var -le $lockout_threshold; $var++) { C:\AtomicRedTeam\atomics\..\ExternalPayloads\plink.exe -ssh "atomic.local" -l root -pw f0b443ae-9565-11ee-b9d1-0242ac120002 }}`

**Process Creation Chain**: Sysmon EID 1 events show the process hierarchy from the initial PowerShell test framework through to the child PowerShell process executing the attack script, with clear parent-child relationships via ProcessGuid values.

**System Discovery**: A `whoami.exe` execution (Sysmon EID 1) indicates reconnaissance activity, likely part of the test framework validation.

## What This Dataset Does Not Contain

This dataset is missing the actual plink.exe process executions and network connection attempts. The Sysmon ProcessCreate events only capture PowerShell processes and whoami.exe, but not the 5 expected plink.exe process creations that would execute the SSH brute force attempts. This absence suggests either the sysmon-modular configuration filtered out plink.exe (which isn't typically in the LOLBins include list), or Windows Defender blocked the plink.exe executions entirely. 

No network connection events (Sysmon EID 3) are present, which would normally show the SSH connection attempts to "atomic.local" on port 22. Additionally, there are no authentication failure events in the Security log that would typically accompany failed SSH authentication attempts, though these might be logged on the target ESXi system rather than the attacking Windows host.

## Assessment

The dataset provides excellent evidence for the PowerShell-based attack orchestration and script content but lacks telemetry for the actual brute force attempts. The Security 4688 events with command-line logging and PowerShell 4104 script block logging capture the complete attack methodology, including the hardcoded credentials and target system. However, the missing plink.exe process executions and network connections significantly limit the dataset's utility for detecting the core brute force behavior. This pattern is common when endpoint protection interferes with technique execution or when monitoring configurations don't capture all relevant processes.

## Detection Opportunities Present in This Data

1. **PowerShell Script Block Analysis**: Monitor PowerShell EID 4104 for script blocks containing SSH connection tools (plink.exe, ssh.exe) combined with credential parameters (-pw, -l) and loop constructs indicating automated attempts.

2. **Command Line Pattern Detection**: Alert on Security EID 4688 process creation events where CommandLine contains "plink.exe" with SSH parameters, particularly when combined with hardcoded passwords or credential patterns.

3. **PowerShell Process Spawning**: Detect PowerShell processes (EID 4688) that spawn child PowerShell instances executing network tools, especially when command lines contain remote hostnames and authentication parameters.

4. **Credential Exposure in Logs**: Search for hardcoded passwords in process command lines or PowerShell script blocks, as demonstrated by the exposed "f0b443ae-9565-11ee-b9d1-0242ac120002" password value.

5. **ESXi Target Identification**: Monitor for references to virtualization-related hostnames or IP addresses in PowerShell scripts and process command lines, combined with SSH client tool usage.

6. **Automated Loop Detection**: Identify PowerShell script blocks containing for-loops or similar iteration constructs combined with network connection tools and credential parameters, indicating automated password guessing attempts.
