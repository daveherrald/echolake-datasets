# T1098-1: Account Manipulation — Admin Account Manipulate

## Technique Context

T1098 Account Manipulation represents a critical persistence technique where attackers modify existing accounts to maintain access or escalate privileges. The .001 sub-technique specifically targets administrative accounts, typically involving renaming, description changes, or privilege modifications to built-in or privileged accounts. This technique is particularly dangerous because it operates within legitimate account management functions, making detection challenging. Attackers often target the built-in Administrator account due to its inherent privileges and reduced monitoring compared to domain accounts. Detection communities focus on monitoring account modification events, unusual administrative cmdlet usage, and changes to high-privilege account properties.

## What This Dataset Contains

This dataset captures a successful PowerShell-based administrative account manipulation attack. The technique uses a complex PowerShell script that:

1. **Generates random identifiers**: `Get-Random -Minimum 2 -Maximum 9999` calls create variables `$x`, `$y`, `$z`, `$w` for obfuscation
2. **Enumerates local administrators**: `Get-LocalGroupMember -Group Administrators` with filtering for local user accounts (`$_.ObjectClass -match "User" -and $_.PrincipalSource -match "Local"`)
3. **Targets Administrator accounts**: Filters for accounts matching `*Administrator*` pattern
4. **Preserves original information**: `Set-LocalUser -Name $account -Description "atr:$account;$originalDescription".Substring(0,48)` stores the original account name in the description field
5. **Renames the account**: `Rename-LocalUser -Name $account -NewName "HaHa_647372781371"`

The PowerShell events in EID 4103 show detailed command execution with parameter bindings, revealing the complete attack flow. Security EID 4688 captures the PowerShell process creation with the full command line containing the obfuscated script. Sysmon captures process creation (EID 1) for both `whoami.exe` and the child PowerShell process executing the manipulation script, along with extensive .NET assembly loading events (EID 7) and process access events (EID 10) showing PowerShell's interaction with child processes.

## What This Dataset Does Not Contain

The dataset lacks several critical detection signals typically associated with account manipulation:
- **Account management audit events**: No Security EIDs 4720, 4722, 4724, 4725, 4726, 4738, or 4781 that would normally capture account creation, enabling, disabling, or modification activities
- **SAM database access events**: Missing file system monitoring of SAM registry hive modifications
- **Group membership changes**: No EID 4732/4733 events for group modifications
- **Privilege assignment events**: Missing EID 4704/4705 for user right assignments

This absence suggests either the audit policy doesn't include account management events (confirmed by `account_management: none` in the metadata) or the technique successfully bypassed traditional account monitoring by using PowerShell cmdlets rather than direct API calls.

## Assessment

This dataset provides excellent coverage of the PowerShell execution layer but limited visibility into the underlying account management operations. The PowerShell logging (EIDs 4103/4104) offers exceptional detail for detecting the technique through command-line analysis and script block inspection. However, the missing account management audit events represent a significant gap that would challenge detection in environments relying solely on traditional Windows account auditing. The combination of Security process creation events and PowerShell detailed logging creates a strong detection foundation, though defenders would need to focus on PowerShell-based indicators rather than native account modification events.

## Detection Opportunities Present in This Data

1. **PowerShell cmdlet sequence detection**: Monitor for `Get-LocalGroupMember`, `Get-LocalUser`, `Set-LocalUser`, and `Rename-LocalUser` cmdlets executed in rapid succession within the same PowerShell session

2. **Administrator account targeting**: Alert on PowerShell commands filtering for accounts matching `*Administrator*` patterns combined with account modification cmdlets

3. **Account description manipulation**: Detect `Set-LocalUser` operations that modify the Description parameter, especially with suspicious prefixes like "atr:" indicating attack tool artifacts

4. **Random string generation in account contexts**: Flag `Get-Random` cmdlet usage immediately followed by local user management operations, indicating obfuscation attempts

5. **Suspicious account renaming patterns**: Monitor `Rename-LocalUser` cmdlet usage, particularly when renaming privileged accounts to non-standard names like "HaHa_*"

6. **PowerShell process spawning pattern**: Detect PowerShell processes spawning child PowerShell instances with embedded account manipulation scripts in the command line

7. **High-privilege PowerShell execution**: Alert on PowerShell running as SYSTEM executing local user management cmdlets, which is uncommon in legitimate administration

8. **Script block content analysis**: Monitor PowerShell script blocks containing combinations of group enumeration, user querying, and account modification operations within a single execution context
