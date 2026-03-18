# T1087.002-12: Domain Account — Enumerate Active Directory Users with ADSISearcher

## Technique Context

T1087.002 (Account Discovery: Domain Account) represents a critical reconnaissance technique where adversaries enumerate domain user accounts to understand the Active Directory environment. The [adsisearcher] PowerShell type accelerator provides a native Windows capability for LDAP queries against Active Directory, making it a common choice for both legitimate administration and adversary enumeration. Detection teams focus on identifying LDAP queries with broad user enumeration patterns, PowerShell execution with AD-related cmdlets, and processes accessing directory services APIs. This technique is particularly significant because it requires no additional tools and produces minimal forensic artifacts while providing valuable intelligence about domain users.

## What This Dataset Contains

This dataset captures a PowerShell execution using the [adsisearcher] .NET class to enumerate Active Directory users. The core technique is visible in Security event 4688 with command line `"powershell.exe" & {([adsisearcher]"objectcategory=user").FindAll(); ([adsisearcher]"objectcategory=user").FindOne()}`. PowerShell script block logging (event 4104) shows the exact commands: `& {([adsisearcher]"objectcategory=user").FindAll(); ([adsisearcher]"objectcategory=user").FindOne()}` and `{([adsisearcher]"objectcategory=user").FindAll(); ([adsisearcher]"objectcategory=user").FindOne()}`.

The execution creates a child PowerShell process (PID 5196) that performs the actual LDAP queries. Sysmon captures extensive DLL loading events showing the .NET framework initialization (mscoree.dll, mscoreei.dll, clr.dll, System.Management.Automation.ni.dll) and Windows Defender AMSI integration (MpOAV.dll, MpClient.dll). The file creation event for `acme.local.sch` in the SchCache directory indicates Active Directory schema caching, providing evidence of domain queries. Process access events (Sysmon EID 10) show the parent PowerShell process accessing the child PowerShell process with full access rights (0x1FFFFF).

## What This Dataset Does Not Contain

The dataset lacks the actual results of the LDAP enumeration - no events show which user accounts were discovered or the specific LDAP response data. There are no network connection events despite the Active Directory queries, likely because domain communication occurs through existing authenticated channels. The PowerShell operational log contains primarily test framework boilerplate and format-related script blocks rather than detailed execution traces of the ADSI queries. DNS query events are absent, suggesting the domain controller resolution used cached entries. Windows Defender appears to have allowed the execution without generating detection events or blocking the technique.

## Assessment

This dataset provides excellent telemetry for detecting PowerShell-based Active Directory enumeration techniques. The Security channel's command-line logging captures the exact ADSI syntax used, while Sysmon process creation events show the execution chain. The PowerShell script block logging preserves the technique commands, though buried among formatting artifacts. The file system artifacts (schema cache files) offer additional corroborating evidence of AD queries. The combination of process telemetry, command-line logging, and PowerShell execution traces creates multiple detection opportunities. However, the lack of network-level telemetry and LDAP query details limits understanding of the enumeration scope and results.

## Detection Opportunities Present in This Data

1. **PowerShell Script Block Detection**: Monitor PowerShell event 4104 for script blocks containing `[adsisearcher]` with LDAP filter patterns like `objectcategory=user` or `objectclass=user`

2. **Command Line Analysis**: Detect Security event 4688 process creation with command lines containing `adsisearcher` followed by common enumeration filters (`objectcategory=user`, `objectclass=person`, etc.)

3. **PowerShell Process Chaining**: Alert on PowerShell spawning child PowerShell processes (Sysmon EID 1) where the parent and child both involve `powershell.exe` with ADSI-related command lines

4. **Schema Cache File Creation**: Monitor Sysmon EID 11 file creation events for `*.sch` files in `SchCache` directories, indicating Active Directory schema access

5. **.NET Framework Loading Pattern**: Correlate Sysmon EID 7 image loads of `System.Management.Automation.ni.dll` with subsequent AD-related PowerShell execution

6. **Process Access for PowerShell Injection**: Detect Sysmon EID 10 process access events where PowerShell processes access other PowerShell processes with high privilege levels (0x1FFFFF) combined with AD enumeration indicators
