# T1018-1: Remote System Discovery — Remote System Discovery - net

## Technique Context

T1018 Remote System Discovery is a fundamental Discovery technique where adversaries enumerate systems within their target network to identify potential lateral movement targets. The `net` command suite is one of the most common methods for this reconnaissance, particularly `net view` which displays available network shares and systems. This technique appears frequently in real-world attacks as part of initial network mapping activities following initial access or privilege escalation.

Detection engineers focus on monitoring execution of network enumeration commands, especially when they originate from suspicious processes or occur in rapid succession. The combination of `net view` and `net view /domain` is particularly indicative of systematic network reconnaissance, as it attempts to enumerate both local network resources and domain-wide systems.

## What This Dataset Contains

This dataset captures a complete Remote System Discovery sequence executed through PowerShell calling cmd.exe with chained `net` commands. The Security channel provides the primary detection telemetry through process creation events:

- **Security 4688**: PowerShell (PID 4204) spawning `"cmd.exe" /c net view /domain & net view` 
- **Security 4688**: cmd.exe spawning `net view /domain` (PID 7004) which exits with status 0x2
- **Security 4688**: cmd.exe spawning `net view` (PID 6428) which also exits with status 0x2

Sysmon provides complementary process creation events with additional context:

- **Sysmon EID 1**: cmd.exe creation with full command line `"cmd.exe" /c net view /domain & net view`
- **Sysmon EID 1**: Both net.exe processes with their respective arguments, tagged with `technique_id=T1018,technique_name=Remote System Discovery`

The exit codes 0x2 from both net.exe processes indicate "file not found" errors, likely because the test environment lacks domain controllers or network shares to enumerate. Sysmon EID 10 events show PowerShell accessing both the cmd.exe and net.exe processes with full access (0x1FFFFF), demonstrating the parent-child relationship chain.

## What This Dataset Does Not Contain

This dataset lacks several elements that would appear in real-world Remote System Discovery attempts:

- **Network traffic** from the actual enumeration attempts (DNS queries, SMB negotiations, LDAP queries) since Windows Defender or network configuration blocked the discovery
- **Successful output** from the net commands due to the test environment configuration
- **Follow-up commands** that typically accompany successful network discovery (additional net commands targeting specific systems, ping sweeps, etc.)
- **File system artifacts** like cached results or temporary files that might be created during extensive enumeration

The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) rather than the actual discovery commands being executed.

## Assessment

This dataset provides excellent telemetry for detecting T1018 Remote System Discovery attempts using net commands. The Security 4688 events with command-line logging capture the essential detection artifacts, while Sysmon adds valuable process relationship context and built-in technique tagging. The presence of both successful process creation events and the failure exit codes creates a realistic scenario where detection would still trigger even when the technique fails to produce useful reconnaissance data.

The process chain (PowerShell → cmd.exe → net.exe) is clearly visible across multiple log sources, providing redundant detection opportunities. This is particularly valuable since attackers often use various process execution methods to run net commands.

## Detection Opportunities Present in This Data

1. **Process creation of net.exe with discovery arguments** - Security 4688 and Sysmon EID 1 both capture `net view` and `net view /domain` execution with full command lines

2. **Chained network enumeration commands** - The compound command `net view /domain & net view` in a single cmd.exe execution indicates systematic discovery activity

3. **PowerShell spawning system enumeration tools** - Process chain showing PowerShell creating cmd.exe which then creates net.exe processes for network discovery

4. **Process access patterns during enumeration** - Sysmon EID 10 showing PowerShell accessing spawned discovery processes with full privileges (0x1FFFFF)

5. **Rapid succession of related discovery commands** - Temporal correlation of multiple net commands executed within seconds of each other

6. **Discovery tool execution from unexpected parents** - net.exe spawned by cmd.exe spawned by PowerShell rather than direct interactive command line usage
