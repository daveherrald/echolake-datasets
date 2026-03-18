# T1018-18: Remote System Discovery — Enumerate Active Directory Computers with ADSISearcher

## Technique Context

T1018 Remote System Discovery is a foundational reconnaissance technique where adversaries enumerate systems on networks to identify targets for lateral movement. This specific test (T1018-18) demonstrates using PowerShell's `[adsisearcher]` .NET accelerator to query Active Directory for computer objects. The `[adsisearcher]` type accelerator provides a simplified interface to System.DirectoryServices.DirectorySearcher, making it a popular choice for both legitimate administrators and attackers performing AD enumeration.

Detection engineers focus on monitoring PowerShell execution with ADSI/LDAP-related cmdlets and .NET calls, command-line patterns containing `adsisearcher` or `objectcategory=computer`, and unusual process access patterns during AD queries. This technique is commonly observed in post-exploitation frameworks and living-off-the-land attack patterns.

## What This Dataset Contains

The dataset captures successful execution of PowerShell-based Active Directory computer enumeration using `[adsisearcher]`. Key evidence includes:

**Process execution chain:** Security EID 4688 shows the spawning of a child PowerShell process with command line `"powershell.exe" & {([adsisearcher]"objectcategory=computer").FindAll(); ([adsisearcher]"objectcategory=computer").FindOne()}` created by parent process PID 0x1f40.

**PowerShell script block logging:** EID 4104 captures the actual technique execution with script block `{([adsisearcher]"objectcategory=computer").FindAll(); ([adsisearcher]"objectcategory=computer").FindOne()}` and the ampersand invocation variant, providing clear evidence of the ADSI searcher instantiation and method calls.

**Sysmon process creation:** EID 1 shows the child PowerShell process (PID 7988) with the full command line revealing the Active Directory computer enumeration technique.

**File system artifacts:** Sysmon EID 11 shows creation of `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\SchCache\acme.local.sch` indicating Active Directory schema caching during the query operation.

**WMI provider activation:** Sysmon EID 1 captures WmiPrvSE.exe process creation, indicating potential WMI-based directory services interaction during the ADSI query execution.

## What This Dataset Does Not Contain

The dataset does not contain network-level LDAP query telemetry — no DNS queries to domain controllers, no LDAP bind operations, and no actual directory service protocol traffic. The Sysmon configuration appears to exclude network connection logging for this specific activity, missing crucial network indicators that would show the actual AD communication.

Missing are any Windows event logs from the Directory Service channel that might record LDAP search operations. The dataset also lacks any failed authentication attempts or access denied errors that might occur with insufficient privileges, suggesting the SYSTEM context had adequate permissions for the enumeration.

Process access events (Sysmon EID 10) show interaction with child processes but don't capture any cross-process injection or memory access that might indicate more sophisticated evasion techniques.

## Assessment

This dataset provides good coverage of the PowerShell execution aspects of AD computer enumeration through multiple complementary data sources. The Security channel's process creation with full command-line logging combined with PowerShell script block logging creates robust detection opportunities. However, the lack of network telemetry significantly limits visibility into the actual directory service communication, which is a critical component for comprehensive detection of this technique.

The file system artifacts showing schema cache creation provide useful supplementary evidence but alone wouldn't be sufficient for high-confidence detection. The dataset is most valuable for detecting the execution method rather than the network reconnaissance itself.

## Detection Opportunities Present in This Data

1. **PowerShell script block analysis** - Monitor EID 4104 for script blocks containing `[adsisearcher]` combined with `objectcategory=computer` or similar AD object queries

2. **Command-line pattern matching** - Detect Security EID 4688 or Sysmon EID 1 process creation events with command lines containing both `adsisearcher` and Active Directory object category filters

3. **PowerShell execution with AD enumeration patterns** - Alert on PowerShell processes executing with arguments containing `FindAll()` and `FindOne()` methods in conjunction with directory service searcher objects

4. **Schema cache file creation timing** - Correlate Sysmon EID 11 creation of `.sch` files in SchCache directory with concurrent PowerShell execution for additional context

5. **Parent-child process relationship analysis** - Monitor for PowerShell spawning child PowerShell processes with ADSI-related command lines, indicating potential scripted reconnaissance activities

6. **WMI provider activation correlation** - Link WmiPrvSE.exe process creation with concurrent PowerShell ADSI operations as potential indicator of directory service enumeration activity
