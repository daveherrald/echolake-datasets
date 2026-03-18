# T1070.005-1: Network Share Connection Removal — Add Network Share

## Technique Context

T1070.005 (Network Share Connection Removal) is a defense evasion technique where attackers remove evidence of network share connections to hide their lateral movement activities. The technique typically involves using commands like `net use /delete` to disconnect mapped drives or remove persistent network connections from the system. Detection communities focus on monitoring network share management commands, particularly those that remove or modify existing connections, as these can indicate an attacker attempting to cover their tracks after accessing remote systems or shares.

However, this specific Atomic Red Team test (T1070.005-1) appears to be misnamed, as it actually demonstrates adding network shares rather than removing them, making it more relevant to techniques like T1135 (Network Share Discovery) or lateral movement preparation.

## What This Dataset Contains

This dataset captures the execution of commands that create and manage network shares rather than remove them. The key telemetry shows:

**Process execution chain:** PowerShell → cmd.exe → net.exe → net1.exe with the command `"cmd.exe" /c net use c: \\test\share & net share test=\\test\share /REMARK:"test share" /CACHE:No`

**Security Events (4688):** Process creation events showing the full command line arguments, including the compound command that attempts to map a drive (`net use c: \\test\share`) and create a local share (`net share test=\\test\share /REMARK:"test share" /CACHE:No`)

**Process exit codes:** The net.exe processes exit with code 0x2 and 0x1, indicating failures in the network operations, likely because the target share `\\test\share` doesn't exist in this test environment

**Sysmon Events:** Process creation (EID 1) for whoami.exe, cmd.exe, net.exe, and net1.exe, plus process access events (EID 10) showing PowerShell accessing the child processes with full rights (0x1FFFFF)

**PowerShell telemetry:** Standard test framework activity with Set-ExecutionPolicy commands but no substantive script block content related to the network share operations

## What This Dataset Does Not Contain

This dataset lacks several elements that would be present in a genuine network share removal scenario:

**No actual share removal commands:** The test creates shares rather than removing them with commands like `net use /delete` or `net share sharename /delete`

**No network connection telemetry:** Since the target share doesn't exist, there are no successful network connections, SMB traffic, or authentication events that would normally accompany share operations

**No registry modifications:** Network share mappings and persistent connections typically involve registry changes under `HKCU\Network` or `HKLM\SYSTEM\CurrentControlSet\Services\lanmanserver\Shares`, which aren't captured here

**Limited error details:** While the exit codes indicate failures, there's no detailed error output or event log entries explaining why the network operations failed

## Assessment

This dataset provides limited value for detecting T1070.005 (Network Share Connection Removal) since it demonstrates the opposite behavior—share creation rather than removal. The telemetry quality is good for process execution monitoring, with clear command-line visibility in both Security 4688 and Sysmon EID 1 events. However, the failed network operations limit its utility for understanding successful share management activities. The dataset would be more valuable if renamed to reflect its actual behavior (share creation/mapping) and if it included successful operations against existing network resources.

## Detection Opportunities Present in This Data

1. **Network share management command execution** - Monitor for net.exe/net1.exe processes with "share" or "use" parameters in Security 4688 and Sysmon EID 1 events

2. **Compound command execution patterns** - Detect cmd.exe processes executing multiple network commands chained with "&" operators

3. **Process access patterns** - Identify PowerShell processes accessing net.exe child processes with high privileges (0x1FFFFF) in Sysmon EID 10

4. **Failed network operations** - Track net.exe processes exiting with error codes (0x1, 0x2) that may indicate reconnaissance or cleanup attempts against non-existent shares

5. **PowerShell spawning network utilities** - Monitor for PowerShell → cmd.exe → net.exe process chains that could indicate scripted network share operations
