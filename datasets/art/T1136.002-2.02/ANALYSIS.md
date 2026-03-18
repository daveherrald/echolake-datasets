# T1136.002-2: Domain Account — Create a new account similar to ANONYMOUS LOGON

## Technique Context

Creating domain accounts (T1136.002) is a persistence technique where attackers with domain credentials establish additional user accounts in Active Directory for long-term access. This specific test adds a camouflage dimension: the account name `ANONYMOUS  LOGON` (with two spaces) mimics the well-known Windows built-in account `ANONYMOUS LOGON`, making the malicious account visually blend with legitimate system accounts in directory listings and log queries. The technique uses the standard `net user` command with `/add /domain` to create the account against the domain controller. With Defender disabled, the command executes without interference; however, whether the domain account is actually created depends on whether the executing account has domain write privileges.

## What This Dataset Contains

With Windows Defender disabled, this dataset captures the full execution of the `net user "ANONYMOUS  LOGON" /add /domain` command chain from ACME-WS06.acme.local, including both the account creation attempt and cleanup.

**Complete process execution chain in Security EID 4688:** All eight process creation events are captured, providing a clear picture of the execution:

1. PowerShell (PID 16452) spawns `whoami.exe` — pre-execution identity check
2. PowerShell spawns `cmd.exe` with `"cmd.exe" /c net user "ANONYMOUS  LOGON" "T1136_pass123!" /add /domain`
3. cmd.exe spawns `net.exe` with `net  user "ANONYMOUS  LOGON" "T1136_pass123!" /add /domain`
4. net.exe spawns `net1.exe` with `C:\Windows\system32\net1  user "ANONYMOUS  LOGON" "T1136_pass123!" /add /domain`
5. PowerShell spawns `whoami.exe` — post-execution identity check
6. PowerShell spawns `cmd.exe` with `"cmd.exe" /c net user "ANONYMOUS  LOGON" >nul 2>&1 /del /domain` — cleanup
7. cmd.exe spawns `net.exe` with `net  user "ANONYMOUS  LOGON"  /del /domain` — cleanup
8. net.exe spawns `net1.exe` with `C:\Windows\system32\net1  user "ANONYMOUS  LOGON"  /del /domain` — cleanup

**Sysmon EID 1 confirms the same chain:** All eight processes are captured in Sysmon with hashes and full command lines. The `cmd.exe` processes are tagged with `RuleName: technique_id=T1087.001,technique_name=Local Account` (a Sysmon-modular rule hit). The `net.exe` processes are tagged with `RuleName: technique_id=T1018,technique_name=Remote System Discovery`.

**Note on success vs. failure:** The dataset does not contain Security EID 4720 (account created) or EID 4726 (account deleted) events. In the defended dataset, `net1.exe` exited with error code `0x2` indicating failure. The absence of domain account lifecycle events here may indicate the account creation still failed — possibly because the executing SYSTEM account lacked domain write access, or because the domain controller declined the creation — despite Defender being disabled.

**PowerShell test framework logging:** 103 PowerShell events (100 EID 4104, 3 EID 4103) confirm execution policy bypass and Write-Host "DONE" completion.

Compared to the defended dataset (34 Sysmon, 15 Security, 34 PowerShell), this undefended run has fewer total events but Security events match counts: both datasets show 8 EID 4688 events, confirming identical process execution chains. The defended run additionally captured Sysmon EID 3 and EID 22 events, which are not present here.

## What This Dataset Does Not Contain

**Domain account creation confirmation (EID 4720):** No account creation events appear in the local Security log. If the domain account was successfully created, the authoritative EID 4720 event would appear on the domain controller (ACME-DC01 at 192.168.4.10), not on the workstation. If the creation failed (due to insufficient privileges), no EID 4720 would appear anywhere.

**Error codes from net.exe/net1.exe:** The specific exit codes of `net.exe` and `net1.exe` would clarify whether the domain account creation succeeded or failed. These process exit events are not captured in this dataset's samples.

**Domain controller correlation:** The domain controller's Security log would contain the definitive account creation record if the technique succeeded. That DC telemetry is outside the scope of this workstation dataset.

**Kerberos authentication events:** A successful `/add /domain` operation would require the workstation to authenticate to the domain controller. No EID 4648 (explicit credential logon) or Kerberos-related events are present.

## Assessment

This dataset provides excellent process creation telemetry for detecting the `net user /add /domain` technique, including the full command chain from PowerShell through cmd.exe, net.exe, and net1.exe with all arguments visible. The account name `ANONYMOUS  LOGON` is present verbatim in the command lines, making the masquerading attempt detectable by anyone examining the process arguments carefully.

The absence of EID 4720 in the dataset is the key open question: without DC-side telemetry, you cannot confirm from this dataset alone whether the domain account was actually created. For defenders, this illustrates the importance of collecting domain controller Security logs alongside workstation telemetry — workstation-side visibility is necessary but not sufficient for domain account creation detection.

Compared to the defended variant, the execution chains are identical in structure and event count, confirming that Defender was not the reason the domain account creation may have failed. Both runs encountered the same process chain; the potential failure is likely a privilege issue, not a security control.

## Detection Opportunities Present in This Data

- **Security EID 4688 / Sysmon EID 1:** `net.exe` and `net1.exe` executing `user "ANONYMOUS  LOGON" ... /add /domain` — the exact account name, spacing anomaly, and `/domain` flag are all present in command-line logging
- **Security EID 4688 chain:** PowerShell → cmd.exe → net.exe → net1.exe spawned under SYSTEM context is an anomalous process tree for workstation activity; the chain itself is a behavioral signature for `net user`-based account manipulation
- **Command-line string match:** The double-space in `"ANONYMOUS  LOGON"` (two spaces between ANONYMOUS and LOGON) is an intentional camouflage attempt that can be detected by command-line analysis looking for variations on known system account names
- **Cleanup pattern:** The immediate follow-on `net user "ANONYMOUS  LOGON" /del /domain` after creation is an ART test artifact but mirrors attacker cleanup behavior that detection logic should track
- **Sysmon EID 1 tagged process:** Sysmon-modular tags `cmd.exe` with `T1087.001` and `net.exe` with `T1018`, providing pre-classified technique attribution in the Sysmon data
