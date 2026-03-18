# T1134.004-3: Parent PID Spoofing — Parent PID Spoofing - Spawn from Specified Process

## Technique Context

T1134.004 Parent PID Spoofing is a defense evasion and privilege escalation technique where adversaries manipulate process creation to make a new process appear as if it was spawned by a different parent process than the actual one. This technique is commonly used to bypass security controls that rely on process parentage for detection, hide malicious activity within legitimate process hierarchies, or evade application whitelisting solutions that track process lineage.

The detection community focuses on identifying mismatches between expected parent-child relationships, unusual process creation patterns, and API calls associated with process creation manipulation (particularly `CreateProcess` with specific flags, process handle duplication, and token manipulation). Defenders typically look for processes with unexpected parents, privilege escalations without proper lineage, and PowerShell execution patterns that suggest process spoofing.

## What This Dataset Contains

This dataset captures a successful parent PID spoofing demonstration using PowerShell's `Start-ATHProcessUnderSpecificParent` function. The key evidence includes:

**Process Creation Chain:**
- Initial PowerShell process (PID 25932) executes: `"powershell.exe" & {Start-ATHProcessUnderSpecificParent -ParentId $PID -TestGuid 12345678-1234-1234-1234-123456789123}`
- Spawns whoami.exe (PID 14716) with command line `"C:\Windows\system32\whoami.exe"`
- Creates another PowerShell process (PID 29548) with the same command line as the parent

**Critical Sysmon Evidence:**
- Sysmon EID 1 shows whoami.exe with `ParentProcessId: 25932` and `ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- Sysmon EID 1 shows the second PowerShell process with identical parentage
- Sysmon EID 10 captures process access events where the source PowerShell process accesses both spawned processes with `GrantedAccess: 0x1FFFFF`

**Security Event Correlation:**
- Security EID 4688 confirms process creations with matching PIDs and command lines
- Security EID 4703 shows token privilege adjustments including `SeAssignPrimaryTokenPrivilege` and `SeIncreaseQuotaPrivilege`

**PowerShell Activity:**
- PowerShell EID 4104 captures the script block containing the `Start-ATHProcessUnderSpecificParent` function call
- Extensive .NET assembly loading events (Sysmon EID 7) for all PowerShell processes

## What This Dataset Does Not Contain

**Missing Advanced Spoofing Evidence:** The technique appears to work through normal process creation rather than advanced API manipulation, so we don't see evidence of handle duplication, token stealing, or direct PPID modification at the kernel level.

**Limited Sysmon ProcessCreate Coverage:** Due to the sysmon-modular include-mode filtering, we only see ProcessCreate events for processes matching suspicious patterns (whoami.exe for discovery, powershell.exe for execution). Other potential child processes would not be captured if they don't match the filter criteria.

**No LSASS Interaction:** The dataset doesn't show direct LSASS access or token manipulation beyond the privilege adjustments, suggesting this is a higher-level PowerShell-based spoofing technique rather than low-level Windows API abuse.

**No Network Activity:** The spoofing technique itself doesn't generate network events, though real attacks would likely follow up with network communication.

## Assessment

This dataset provides excellent telemetry for detecting parent PID spoofing techniques, particularly PowerShell-based implementations. The combination of Sysmon process creation events, process access events, and Security audit logs creates multiple detection opportunities. The privilege adjustment events (EID 4703) are particularly valuable as they indicate the use of sensitive privileges required for process manipulation.

The data quality is high for building detections focused on process relationships, PowerShell execution patterns, and privilege usage. However, the technique demonstrated here is relatively straightforward compared to more sophisticated kernel-level PPID spoofing, so the dataset is most valuable for detecting PowerShell-based or tool-assisted spoofing rather than custom malware implementations.

## Detection Opportunities Present in This Data

1. **Unusual Parent-Child Process Relationships** - Monitor for processes spawned by PowerShell that don't follow typical execution patterns, especially when combined with system utilities like whoami.exe

2. **PowerShell Script Block Analysis** - Alert on PowerShell script blocks containing functions related to process manipulation, particularly `Start-ATHProcessUnderSpecificParent` or similar process creation functions

3. **Process Access with Full Rights** - Detect when PowerShell processes access other processes with `GrantedAccess: 0x1FFFFF` (PROCESS_ALL_ACCESS), especially targeting system utilities

4. **Token Privilege Escalation** - Monitor Security EID 4703 events for privilege adjustments including `SeAssignPrimaryTokenPrivilege` and `SeIncreaseQuotaPrivilege` from PowerShell processes

5. **Multiple PowerShell Process Spawning** - Flag when a single PowerShell process creates multiple child PowerShell instances with identical command lines

6. **Process Creation Timing Correlation** - Detect rapid succession of process creation events from the same parent with different target processes (whoami.exe followed by powershell.exe)

7. **Cross-Process PowerShell Activity** - Monitor for PowerShell processes that spawn system utilities followed immediately by additional PowerShell instances, indicating potential process manipulation workflows
