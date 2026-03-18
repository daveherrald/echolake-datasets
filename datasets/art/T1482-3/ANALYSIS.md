# T1482-3: Domain Trust Discovery — Powershell enumerate domains and forests

## Technique Context

T1482 (Domain Trust Discovery) includes PowerShell-native enumeration as a common adversary
approach. This test exercises multiple AD enumeration methods in a single script block: PowerView's
`Get-NetDomainTrust` and `Get-NetForestTrust`, the `Get-ADDomain` and `Get-ADGroupMember` cmdlets
from the ActiveDirectory module, and the .NET class
`[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().GetAllTrustRelationships()`.
Using multiple methods in one pass is characteristic of post-exploitation enumeration scripts.

## What This Dataset Contains

This dataset captures telemetry from a PowerShell script block that imports a local copy of
PowerView (`C:\AtomicRedTeam\atomics\..\ExternalPayloads\PowerView.ps1`) and then invokes
the enumeration functions.

**Security channel (4688/4689)** is the authoritative source for the technique command line.
A 4688 event captures the full PowerShell script block passed to the child powershell.exe
process, including the `Import-Module` path and all five enumeration function calls. The
powershell.exe process exits with `0x0`, indicating the script completed without being
terminated by Defender. (A preceding cmd.exe exits `0x1` — this is the ART test framework wrapper
failing its own pre-check, not the technique itself.)

**Sysmon channel** (46 events, IDs 1, 7, 10, 11, 17) is dominated by ImageLoad (ID 7) events
documenting the .NET runtime and PowerShell assembly stack loading as powershell.exe initializes
to run the script. The include-mode ProcessCreate configuration captured the powershell.exe child
process. Sysmon ID 10 (ProcessAccess) records the test framework accessing child processes.

**PowerShell channel** (61 events, IDs 4103/4104) is ART test framework boilerplate (Set-StrictMode
scriptblocks, runtime initialization). The technique-relevant PowerView and ActiveDirectory cmdlet
calls are not captured as distinct script block logging entries — they execute within the child
powershell.exe that was spawned with the full command on the 4688 command line.

## What This Dataset Does Not Contain

- Successful AD trust enumeration results — PowerView's `Get-NetDomainTrust` and the
  ActiveDirectory module cmdlets likely failed or returned empty results because ACME-WS02
  may not have had connectivity to the DC or the required module installed; the exit code 0x0
  reflects PowerShell completing without a termination exception, not successful trust data retrieval
- Domain controller logs showing LDAP queries
- Sysmon DNS (ID 22) or network connection (ID 3) events for DC lookups
- Script block logging for the PowerView functions themselves in this captured channel

## Assessment

This dataset provides **command-line evidence of a multi-method AD enumeration attempt**. The
Security 4688 event contains the full script block including all five function calls and the
PowerView import path, which is high-value for detection. The local PowerView copy (from the
ExternalPayloads directory) distinguishes this from the network-download variant tested in T1482-6
and T1482-7. The PowerShell channel adds volume but no technique-relevant content.

## Detection Opportunities Present in This Data

- **Security 4688**: The command line includes `Import-Module` with the PowerView.ps1 path and
  multiple AD enumeration function names (`Get-NetDomainTrust`, `Get-NetForestTrust`, `Get-ADDomain`,
  `Get-ADGroupMember`, `GetAllTrustRelationships`) — any of these names in a PowerShell command line
  is a strong signal
- **Security 4688**: The `.NET` class call `[System.DirectoryServices.ActiveDirectory.Domain]::
  GetCurrentDomain()` in a command-line argument is detectable by string matching
- **Sysmon ID 1**: powershell.exe spawned by powershell.exe (child of the ART test framework) loading
  PowerView via a local ExternalPayloads path
- **Sysmon ID 7**: ImageLoad events for System.Management.Automation.ni.dll and ActiveDirectory
  module DLLs can supplement process-based detection
