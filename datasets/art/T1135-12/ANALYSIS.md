# T1135-12: Network Share Discovery — Enumerate All Network Shares with Snaffler

## Technique Context

T1135 Network Share Discovery involves adversaries enumerating network shares to identify accessible file repositories, sensitive data locations, and potential lateral movement targets. This technique is fundamental to the discovery phase of many attack chains, helping attackers map available network resources and identify high-value data stores.

Snaffler is a popular open-source tool designed specifically for finding and cataloging interesting files across Windows network shares. It performs automated enumeration by connecting to available shares, recursively searching directories, and identifying files based on patterns that typically indicate sensitive content (credentials, configuration files, documents with keywords, etc.). Detection engineers focus on monitoring for rapid sequential SMB connections, unusual file access patterns, and processes spawning with network discovery command-line arguments.

## What This Dataset Contains

The execution shows a complex PowerShell-based process chain launching Snaffler through multiple command shell layers. Security event 4688 captures the primary execution chain: PowerShell → cmd.exe → PowerShell (with base64-encoded command) → cmd.exe → Snaffler.exe. The decoded command reveals: `cmd /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\Snaffler.exe" -a -o "$env:temp\T1135SnafflerOutput.txt"` where `-a` enables all modules and `-o` specifies output to `C:\Windows\TEMP\T1135SnafflerOutput.txt`.

Sysmon provides detailed process creation events (EID 1) showing the full command-line arguments, including the encoded PowerShell command `IABjAG0AZAAgAC8AYwAgACIAQwA6AFwAQQB0AG8AbQBpAGMAUgBlAGQAVABlAGEAbQBcAGEAdABvAG0AaQBjAHMAXAAuAC4AXABFAHgAdABlAHIAbgBhAGwAUABhAHkAbABvAGEAZABzAFwAUwBuAGEAZgBmAGwAZQByAC4AZQB4AGUAIgAgAC0AYQAgAC0AbwAgACIAJABlAG4AdgA6AHQAZQBtAHAAXABUADEAMQAzADUAUwBuAGEAZgBmAGwAZQByAE8AdQB0AHAAdQB0AC4AdAB4AHQAIgAgAA==`.

PowerShell script block logging (EID 4104) captures the invoke-expression commands and shows the test framework setting execution policy bypass. Process access events (EID 10) show PowerShell accessing cmd.exe and whoami.exe processes with full access rights (0x1FFFFF). Multiple cmd.exe processes exit with status 0x1, indicating the Snaffler execution encountered errors.

## What This Dataset Does Not Contain

Critically missing are network-related events that would typically characterize Snaffler's core functionality. There are no Sysmon network connection events (EID 3), no SMB-related authentication events (4624/4625), and no object access events for file shares (4656/4658). The absence of these events, combined with cmd.exe exit codes of 0x1, suggests Snaffler failed to execute successfully or was blocked before initiating network enumeration.

No Snaffler process creation events appear in Sysmon, indicating the sysmon-modular configuration's include-mode filtering didn't capture the Snaffler.exe execution. The Security audit log shows the cmd.exe processes attempting to launch Snaffler but no evidence of the tool actually running. DNS query events (EID 22) are absent, suggesting no domain controller or file server resolution occurred.

## Assessment

This dataset provides excellent visibility into the attack preparation phase but captures a failed execution scenario. The multi-layered PowerShell and cmd.exe process chains are well-documented through Security 4688 events with full command-line logging, making this valuable for detecting obfuscated execution patterns. However, the lack of actual network share enumeration telemetry limits its utility for understanding Snaffler's operational behavior.

The process access events and encoded PowerShell commands offer solid detection opportunities, but the missing network activity means this dataset doesn't demonstrate the technique's primary impact. For building comprehensive T1135 detections, additional datasets showing successful Snaffler executions with SMB traffic would be needed.

## Detection Opportunities Present in This Data

1. **Base64-encoded PowerShell execution** - Monitor Security 4688 for PowerShell processes with `-encodedCommand` parameter, especially when spawned from cmd.exe

2. **Snaffler command-line patterns** - Detect Security 4688 events containing "Snaffler.exe" with characteristic flags like `-a` (all modules) and `-o` (output file)

3. **Multi-layer process spawning** - Alert on PowerShell → cmd.exe → PowerShell → cmd.exe process chains within short time windows

4. **PowerShell invoke-expression with cmd execution** - Monitor PowerShell script blocks (EID 4104) for invoke-expression commands launching external tools

5. **Suspicious process access patterns** - Detect Sysmon EID 10 events where PowerShell accesses cmd.exe with full permissions (0x1FFFFF)

6. **Tool staging in ExternalPayloads directories** - Watch for executions from paths containing "ExternalPayloads" or "AtomicRedTeam" directories

7. **Output file creation patterns** - Monitor file creation events for files matching patterns like "*SnafflerOutput.txt" in temp directories

8. **Process execution policy bypass** - Correlate Set-ExecutionPolicy bypass commands with subsequent external tool launches
