# T1069.002-11: Domain Groups — Get-ADUser Enumeration via UserAccountControl Flags (AS-REP Roasting Recon)

## Technique Context

T1069.002 (Domain Groups) in this test goes beyond group enumeration to support a specific attack vector: identifying domain accounts vulnerable to AS-REP Roasting. AS-REP Roasting (also part of T1558.004) targets user accounts with the `DONT_REQUIRE_PREAUTH` flag set in their `userAccountControl` attribute (flag value 4194304 in decimal). When Kerberos pre-authentication is disabled for an account, an attacker can request an AS-REP authentication ticket from the domain controller without providing valid credentials, then crack the encrypted portion offline using tools like Hashcat.

The reconnaissance step captured here — identifying which accounts have this flag — is a prerequisite to the actual attack. Attackers use `Get-ADUser` with a `useraccountcontrol` bitwise AND filter to enumerate these vulnerable accounts before attempting credential harvesting. This technique is particularly interesting for detection because it is entirely read-only (no modification occurs), uses a legitimate AD PowerShell cmdlet, and generates LDAP traffic to the domain controller that may not stand out from routine AD administration queries. Detection focuses on the specific UAC flag filter (4194304 or `DONT_REQUIRE_PREAUTH`), unusual use of `Get-ADUser -Properties useraccountcontrol`, and LDAP queries targeting the DC from workstations.

## What This Dataset Contains

The core technique execution is captured in Security EID 4688, which records the PowerShell command line:

```
"powershell.exe" & {Get-ADUser -Filter 'useraccountcontrol -band 4194304' -Properties useraccountcontrol | Format-Table name}
```

The `-band 4194304` filter is the defining indicator: it performs a bitwise AND against the `DONT_REQUIRE_PREAUTH` flag value (4194304 = 0x400000). Sysmon EID 1 confirms this process creation with the same command line.

The Sysmon channel is the richest source in this dataset, with 39 events across six types: 21 EID 7 (image load), 6 EID 13 (registry value set), 4 EID 1 (process create), 4 EID 10 (process access), 3 EID 17 (pipe create), and 1 EID 11 (file create). The 6 EID 13 (registry write) events are notable — this is the highest registry write count in the T1069.002 batch and reflects the `Get-ADUser` command importing and initializing the Active Directory PowerShell module, which writes module configuration state to the registry. These registry writes distinguish this test from purely in-memory ADSI approaches and provide an additional detection surface. The EID 7 image loads document the .NET CLR initialization chain: `mscoree.dll`, `mscoreei.dll`, `clr.dll`, and associated managed code libraries loading into PowerShell.

Named pipe creation events (EID 17, 3 events) record pipes like `\PSHost.134180042017983358.5776.DefaultAppDomain.powershell`, confirming the PowerShell process identity. The EID 11 file creation event reflects schema cache or PowerShell profile activity.

The PowerShell channel contributes 103 EID 4104 events, mostly test framework boilerplate, with the cleanup invocation `Invoke-AtomicTest T1069.002 -TestNumbers 11 -Cleanup -Confirm:$false` logged at the end.

Compared to the defended version (36 sysmon, 11 security, 45 PowerShell events), this undefended run shows slightly more sysmon events (39 vs 36), fewer security events (4 vs 11), and significantly more PowerShell events (103 vs 45). The registry write events in EID 13 appear in the undefended run; in the defended run, Defender's blocking prevented the full AD module initialization from occurring.

## What This Dataset Does Not Contain

The dataset does not include network-level telemetry for the LDAP query that `Get-ADUser` sends to the domain controller. Sysmon network connection monitoring (EID 3) did not capture this traffic, and no EID 22 DNS query events appear in the samples. You will not find the enumeration results — the list of accounts with `DONT_REQUIRE_PREAUTH` set is visible only in console output, not in the telemetry.

The 6 EID 13 registry write events exist in the dataset but their specific `TargetObject` (registry key paths) and `Details` (written values) are not represented in the 20-event sample window; they fall outside the sampled records. Based on context, these likely involve AD module state keys under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\` or similar PowerShell module state paths.

## Assessment

This dataset is high-quality for detection engineering around the AS-REP Roasting prerequisite step. The PowerShell command line captured in EID 4688 is distinctive: the combination of `Get-ADUser`, `-Properties useraccountcontrol`, and the bitwise filter `-band 4194304` is a strong, specific indicator that maps directly to AS-REP Roasting reconnaissance. The EID 13 registry write events provide a unique signal absent in tests that use ADSI instead of the AD module.

The full execution of `Get-ADUser` (evidenced by the higher event counts vs the blocked defended run) means this dataset accurately represents the telemetry an attacker's workstation generates when successfully enumerating AS-REP Roasting candidates.

## Detection Opportunities Present in This Data

1. **EID 4688 / Sysmon EID 1 — `Get-ADUser` with UAC flag filter**: The command line `Get-ADUser -Filter 'useraccountcontrol -band 4194304'` is highly specific to AS-REP Roasting reconnaissance. Any PowerShell process command line containing `4194304` in conjunction with AD cmdlets is a strong indicator.

2. **EID 4104 script block logging — `-band 4194304` pattern**: PowerShell script block logs capturing the `useraccountcontrol -band 4194304` filter provide a detection point that survives obfuscation of the outer command (e.g., if the attacker encodes the outer wrapper but not the filter string).

3. **Sysmon EID 13 — registry writes from PowerShell during AD module initialization**: The 6 registry write events generated during `Get-ADUser` execution (from AD module initialization) create a detectable side-effect. A PowerShell process writing to AD-module-related registry paths while also showing command lines targeting domain controllers is anomalous on workstations.

4. **`DoesNotRequirePreAuth` property enumeration**: The companion test (T1069.002-7) queries `DoesNotRequirePreAuth` directly. Both approaches (flag-based and property-based) should be covered — detect either the `-band 4194304` numeric filter or the explicit `DoesNotRequirePreAuth -eq $TRUE` property filter.

5. **Sysmon EID 17 + EID 7 .NET loads + EID 13 registry writes co-occurrence**: When PowerShell shows named pipe creation, .NET CLR initialization, and registry modification events occurring within the same process lifecycle, combined with a command line targeting AD user enumeration, the composite is characteristic of AD module-based reconnaissance.
