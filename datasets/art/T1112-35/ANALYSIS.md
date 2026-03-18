# T1112-35: Modify Registry — Windows Add Registry Value to Load Service in Safe Mode with Network

## Technique Context

T1112 (Modify Registry) encompasses adversary manipulation of the Windows Registry to achieve persistence, defense evasion, or other malicious objectives. This specific test (T1112-35) focuses on a persistence technique where attackers add registry entries to the Safe Mode boot configuration, ensuring their malicious services persist even when Windows is booted into Safe Mode with Networking. This technique is particularly concerning because Safe Mode is often used for malware removal and system recovery, and many security tools don't operate in this environment. Attackers leverage the `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\` registry key to register services that will start automatically in Safe Mode, maintaining persistence through system recovery attempts.

## What This Dataset Contains

This dataset captures a successful registry modification operation executed through PowerShell calling cmd.exe and reg.exe. The primary evidence includes:

**Process Chain**: PowerShell (PID 11104) → cmd.exe (PID 44920) → reg.exe (PID 9800) with the command line `REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\AtomicSafeMode" /VE /T REG_SZ /F /D "Service"`

**Registry Modification**: Sysmon EID 13 captures the actual registry write: `HKLM\System\CurrentControlSet\Control\SafeBoot\Network\AtomicSafeMode\(Default)` set to value "Service"

**Security Events**: Complete process creation chain in Security EID 4688 events with full command lines showing the technique execution path

**Process Access**: Sysmon EID 10 events showing PowerShell accessing both whoami.exe and cmd.exe processes with full access (0x1FFFFF)

**Additional Context**: Sysmon EID 1 process creation events for whoami.exe (system reconnaissance) and the cmd.exe/reg.exe execution chain

## What This Dataset Does Not Contain

The dataset lacks several elements that would provide a complete picture of this technique in real-world scenarios:

**Service Creation**: No evidence of an actual malicious service being created or configured to load in Safe Mode—only the registry key that would allow such a service to start

**File System Activity**: Missing file creation events for any malicious executables that would be launched by this registry modification

**Network Activity**: No DNS queries or network connections that might accompany service installation or C2 communication setup

**Cleanup Operations**: The test appears to perform only the registry addition without demonstrating cleanup or removal of the persistence mechanism

## Assessment

This dataset provides excellent telemetry for detecting the core registry modification aspect of Safe Mode persistence. The combination of Sysmon EID 13 (registry modification) with the complete process chain from Security EID 4688 events gives defenders comprehensive visibility into this technique's execution. The registry path `SafeBoot\Network\` is highly specific and rarely modified legitimately, making this technique relatively straightforward to detect with low false positive rates. However, the dataset doesn't demonstrate the full attack lifecycle, particularly how an attacker would deploy and configure the service that this registry modification enables.

## Detection Opportunities Present in This Data

1. **Registry modification to SafeBoot keys** - Monitor Sysmon EID 13 for writes to `HKLM\System\CurrentControlSet\Control\SafeBoot\*` registry paths, particularly under Network or Minimal subkeys

2. **Process chain analysis** - Detect PowerShell spawning cmd.exe with registry modification commands, especially those targeting SafeBoot registry locations

3. **Command line pattern matching** - Alert on REG ADD commands targeting SafeBoot registry paths with service-related values

4. **Abnormal registry tool usage** - Monitor reg.exe execution with parameters that modify boot configuration settings, particularly when spawned from scripting engines

5. **Cross-process access to system utilities** - Investigate Sysmon EID 10 events showing PowerShell accessing cmd.exe or reg.exe with high privileges during registry operations

6. **Service value creation in SafeBoot** - Specifically monitor for registry values being set to "Service" within SafeBoot registry paths
