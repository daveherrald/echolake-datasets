# T1482-1: Domain Trust Discovery — Windows discover domain trusts with dsquery

## Technique Context

T1482 (Domain Trust Discovery) covers adversary enumeration of trust relationships between Active Directory domains and forests. Understanding trust topology lets an attacker determine which other domains are accessible from their current foothold: if `acme.local` trusts `partner.local`, a compromised `acme.local` account may be leveraged against `partner.local` resources. Domain trust discovery is a standard post-exploitation reconnaissance step performed before lateral movement across domain boundaries.

Test T1482-1 uses `dsquery * -filter "(objectClass=trustedDomain)" -attr *` to query the directory directly for all objects of class `trustedDomain`. `dsquery` is an RSAT tool included in older Windows versions and available as an install-on-demand feature in Windows 10/11 via Remote Server Administration Tools. On a standard Windows 11 workstation without RSAT installed, `dsquery` is not present and the command fails at the binary-not-found stage.

## What This Dataset Contains

This dataset captures the execution attempt on ACME-WS06, a Windows 11 domain workstation in `acme.local` with Defender disabled.

**Security EID 4688** provides the complete process creation evidence. PowerShell (running as `NT AUTHORITY\SYSTEM`) spawns `cmd.exe` with the command:

```
"cmd.exe" /c dsquery * -filter "(objectClass=trustedDomain)" -attr *
```

This event records the full command line including the LDAP filter, unambiguously identifying the intent of the query. A second `cmd.exe` spawn with an empty body (`/c` with no arguments) is also captured — this is the ART test framework cleanup invocation.

Two `whoami.exe` invocations by the PowerShell test framework are present as EID 4688 events, one before and one after the technique execution, providing a timing bracket.

**Sysmon EID 1** captures the `cmd.exe` process creation with the full `dsquery` command line and supporting hash fields (SHA1, MD5, SHA256, IMPHASH). The cmd.exe event is matched by the sysmon-modular include-mode rule for suspicious command-line activity. `dsquery.exe` itself does not appear as a separate Sysmon EID 1 event — `dsquery` is not installed on this workstation, so no child process for it was spawned.

**Sysmon EID 10** (ProcessAccess) shows four events where `powershell.exe` accessed `whoami.exe` and `cmd.exe` with `GrantedAccess 0x1FFFFF` (full access) — standard ART test framework monitoring behavior.

**Sysmon EID 17** captures the PowerShell named pipe (`\PSHost.*.DefaultAppDomain.powershell`).

The PowerShell channel (107 events: 104 EID 4104 + 3 EID 4103) contains only ART test framework boilerplate. The Application channel has one EID 15 event unrelated to the technique.

**Compared to the defended variant** (16 Sysmon / 10 Security / 32 PowerShell): The undefended run has slightly more events (18 Sysmon / 4 Security / 107 PowerShell). The Security count is lower in the undefended run (4 vs. 10), suggesting the defended variant generated more process exit events with Defender-related exit codes. The core technique evidence — the `cmd.exe` command line with the `dsquery` LDAP filter — is present in both variants. Since `dsquery` is not installed on this workstation and Defender would not have needed to intervene, the technique fails the same way in both runs: binary not found.

This is a **failed execution** in both the defended and undefended variants. `dsquery` is not available on standard Windows 11 Enterprise without RSAT, so `cmd.exe` exits with status `0x1` (command not found / non-zero exit). No `dsquery.exe` process was created and no LDAP queries reached the domain controller.

## What This Dataset Does Not Contain

`dsquery.exe` does not appear as a process creation in either Security or Sysmon channels — it was not found on the system. There are no LDAP or network events showing a query reaching the domain controller. No DC-side logs are included — this dataset is workstation telemetry only. If dsquery were installed, you would expect to see Security EID 4688 for `dsquery.exe`, Sysmon EID 1 with the dsquery binary hash, and potentially Sysmon EID 3 showing an LDAP connection to the DC. None of these are present.

## Assessment

This dataset captures the attempt telemetry for `dsquery`-based domain trust discovery on a workstation where the tool is absent. The command-line evidence in Security EID 4688 is complete and unambiguous — the LDAP filter `(objectClass=trustedDomain)` and the `-attr *` argument are preserved. Defenders can detect this pattern regardless of whether `dsquery` is installed, because the evidence lives in the `cmd.exe` command line. The exit code `0x1` distinguishes this from a successful execution, but the detection signal is in the invocation, not the outcome. In a real attack, you would see the same command line on a workstation where the tool happens to be available.

## Detection Opportunities Present in This Data

- **Security EID 4688**: `cmd.exe` command line containing `dsquery` with `-filter "(objectClass=trustedDomain)"` is a high-fidelity indicator regardless of execution outcome. The combination of `dsquery`, `objectClass=trustedDomain`, and `-attr *` in a single command is effectively unique to this enumeration pattern.
- **Sysmon EID 1**: `cmd.exe` spawned by PowerShell with the full `dsquery` command line. Hash data in Sysmon provides additional correlation capability.
- **Sysmon EID 10**: `powershell.exe` with full access (`0x1FFFFF`) to `cmd.exe` processes is consistent with the ART test framework pattern and other scripted lateral movement tooling.
- The absence of `dsquery.exe` in subsequent events (no EID 4688/1 for `dsquery.exe`) combined with the non-zero exit code on `cmd.exe` allows you to distinguish not-installed from blocked-by-defender (which would show `0xC0000022`).
