# T1069.002-7: Domain Groups — Enumerate Users Not Requiring Kerberos Pre-Authentication (ASRepRoast)

## Technique Context

T1069.002 (Domain Groups) here supports AS-REP Roasting reconnaissance by enumerating domain users with the `DONT_REQUIRE_PREAUTH` flag set (`DoesNotRequirePreAuth` in PowerShell AD module terminology). This is a prerequisite reconnaissance step for the actual AS-REP Roasting attack (T1558.004): an attacker needs to know which accounts are vulnerable before they can request AS-REP tickets to crack offline.

Where T1069.002-11 uses a numeric `useraccountcontrol -band 4194304` filter, this test uses the named property directly: `Get-ADUser -f * -pr DoesNotRequirePreAuth | where {$_.DoesNotRequirePreAuth -eq $TRUE}`. Querying all users (`-f *`) with a specific property flag is common in real intrusions — it sweeps the entire user population rather than requiring prior knowledge of specific accounts. The `-pr DoesNotRequirePreAuth` flag requests the specific AD attribute that controls Kerberos pre-authentication requirement. Any returned accounts can then be targeted for AS-REP ticket requests without needing their credentials.

Detection focuses on the `Get-ADUser` cmdlet with `DoesNotRequirePreAuth` property retrieval, the LDAP query to domain controllers targeting the `userAccountControl` attribute, and the AS-REP Roasting enumeration pattern (`DoesNotRequirePreAuth -eq $TRUE`).

## What This Dataset Contains

Security EID 4688 captures the PowerShell command:

```
"powershell.exe" & {get-aduser -f * -pr DoesNotRequirePreAuth | where {$_.DoesNotRequirePreAuth -eq $TRUE}}
```

This queries all AD users with the `DoesNotRequirePreAuth` property and filters for those where it is `TRUE`. Sysmon EID 1 confirms the process creation with matching command line. The parent-child structure shows the ART test framework spawning a child PowerShell with this command.

The Application channel contains EID 15: "Updated Windows Defender status successfully to SECURITY_PRODUCT_STATE_ON." — the same test framework artifact as T1069.002-6 and T1069.002-13.

Sysmon provides 33 events across five types: 21 EID 7 (image load), 4 EID 1 (process create), 4 EID 10 (process access), 3 EID 17 (pipe create), and 1 EID 11 (file create). The event volume is higher than the PowerView tests (33 vs ~20-24), consistent with the AD module initialization overhead (similar to T1069.002-11 with 39 events). The .NET CLR DLL loads (`mscoree.dll`, `mscoreei.dll`, `clr.dll`) appear in the EID 7 events. Three named pipe creation events (EID 17) confirm multiple PowerShell process instances. The EID 11 file creation event reflects schema cache activity from the AD module query.

Notably, there are **no EID 8 (CreateRemoteThread) events** in this dataset — distinguishing it from the PowerView-based tests and confirming that the process injection behavior is specific to PowerView rather than AD module execution.

The PowerShell channel has 103 EID 4104 events, matching T1069.002-11 (also a Get-ADUser test). The cleanup invocation is logged: `Invoke-AtomicTest T1069.002 -TestNumbers 7 -Cleanup -Confirm:$false`.

Compared to the defended version (46 sysmon, 10 security, 45 PowerShell events), this undefended run shows notably fewer sysmon events (33 vs 46), fewer security events (4 vs 10), and more PowerShell events (103 vs 45). The defended sysmon count is higher because Defender's monitoring generated additional events; the higher undefended PS count confirms the full AD query executed.

## What This Dataset Does Not Contain

LDAP network traffic is absent from the samples. The `Get-ADUser` query contacts the domain controller to retrieve all user objects with their `userAccountControl` attributes; this LDAP traffic is not captured in Sysmon EID 3 events. The actual enumeration results — the list of accounts with `DoesNotRequirePreAuth = TRUE` — are not present in any telemetry channel.

The EID 13 registry write events that appeared in T1069.002-11 do not appear in the EID breakdown for this dataset, despite both tests using `Get-ADUser`. This may reflect minor differences in the AD module initialization path between the two executions or sample windowing effects.

## Assessment

This dataset provides clean, successful execution evidence for AS-REP Roasting reconnaissance via the `DoesNotRequirePreAuth` property approach. The command line is highly specific and actionable: `Get-ADUser -f * -pr DoesNotRequirePreAuth | where {$_.DoesNotRequirePreAuth -eq $TRUE}` is essentially unambiguous in context. The dataset complements T1069.002-11 by providing the named-property variant of the same underlying attack.

The absence of EID 8 CreateRemoteThread events (present in all PowerView tests, absent in AD cmdlet tests) is a useful analytical data point: it shows that the process injection behavior captured in T1069.002-4 through -13 is specific to PowerView's execution model, not a general PowerShell AD enumeration artifact.

## Detection Opportunities Present in This Data

1. **EID 4688 / Sysmon EID 1 — `DoesNotRequirePreAuth` in PowerShell command line**: The property name in a `Get-ADUser` command line or script block is an unambiguous AS-REP Roasting recon indicator. This string does not appear in legitimate administrative workflows except when specifically managing Kerberos pre-authentication settings.

2. **EID 4104 — script block containing `DoesNotRequirePreAuth -eq $TRUE`**: Script block logging captures the filter expression. This is more specific than just detecting `Get-ADUser` — the `DoesNotRequirePreAuth -eq $TRUE` filter uniquely identifies the enumeration intent.

3. **AD module-based `Get-ADUser -f *` (all users) from workstation**: Querying all domain users from a workstation context is unusual. `Get-ADUser -f *` (or its equivalent `-Filter *`) performs a full user object dump from the DC. Combined with property-specific filters targeting security attributes, this pattern distinguishes reconnaissance from routine administration.

4. **Correlation with AS-REP Roasting attack execution**: A detection workflow that correlates this enumeration event (getting the target list) with subsequent Kerberos AS-REP requests from the same host would capture the full attack chain. T1069.002-7 captures step one; pairing it with Kerberos log monitoring on the DC captures step two.

5. **Temporal proximity of `DoesNotRequirePreAuth` enumeration and AS-REP request**: If LDAP queries for `userAccountControl` attributes (even without full script block visibility) are followed within minutes by unusual Kerberos AS-REP traffic from the same source, the combination identifies the attack pattern even when individual events are ambiguous.
