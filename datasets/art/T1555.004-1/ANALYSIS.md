# T1555.004-1: Windows Credential Manager — Access Saved Credentials via VaultCmd

## Technique Context

T1555.004 (Windows Credential Manager) covers adversary access to credentials stored in the Windows Vault — a protected storage facility for web, network, and application credentials managed by the Windows Credential Manager service. `VaultCmd.exe` is a legitimate Windows binary (`C:\Windows\System32\VaultCmd.exe`) that provides command-line access to vault contents. Attackers use it to enumerate stored credentials with minimal footprint, as it is a Microsoft-signed binary present on all Windows installations.

## What This Dataset Contains

The dataset spans four seconds on 2026-03-14 on ACME-WS02 (Windows 11 Enterprise, domain acme.local). The core action was `VaultCmd.exe` invoked with the `/listcreds:"Windows Credentials"` flag, executed via cmd.exe from a PowerShell parent:

From Security EID 4688:
- `cmd.exe /c vaultcmd /listcreds:"Windows Credentials"` (spawned by powershell.exe)
- `vaultcmd /listcreds:"Windows Credentials"` (spawned by cmd.exe)

Sysmon EID 1 captured `VaultCmd.exe` (tagged `T1083` — File and Directory Discovery) and `cmd.exe` (also T1083). Both confirm the Sysmon include-mode rules matched the LOLBin.

Additional Sysmon events follow the same test framework pattern: EID 7 (DLL loads into PowerShell), EID 10 (cross-process PowerShell access, T1055.001), EID 11 (PowerShell transcript files), EID 17 (named PSHost pipes). EID 1 for `whoami.exe` (T1033) was captured as part of the standard pre-test reconnaissance.

Security events include EID 4688/4689 for process lifecycle and EID 4703 for token right adjustment under SYSTEM.

## What This Dataset Does Not Contain (and Why)

**No output from VaultCmd.** The vault listing result is written to stdout and is not captured in event logs. Object access auditing is disabled, so no EID 4663 records show access to vault database files.

**No DPAPI events.** While Credential Manager uses DPAPI for storage protection, enumerating vault metadata with VaultCmd does not necessarily trigger DPAPI decryption events — the `/listcreds` flag lists vault names, not decrypted credentials.

**No Security EID 4776 (credential validation).** VaultCmd reads vault metadata but does not re-authenticate, so no credential validation event is generated.

**No Sysmon ProcessCreate for PowerShell itself.** The test's parent PowerShell instance was not captured by Sysmon's include-mode rules for this invocation — only `whoami.exe` and `cmd.exe`/`VaultCmd.exe` were tagged.

## Assessment

This is a clean, low-noise dataset for a native Windows credential enumeration technique. The critical telemetry is in Security EID 4688 (with command-line logging showing the exact VaultCmd invocation) and Sysmon EID 1. The `vaultcmd /listcreds:"Windows Credentials"` command line is specific enough to be a reliable detection string. The fact that Sysmon captured VaultCmd under the T1083 rule (File and Directory Discovery) rather than a dedicated credential-access rule reflects that sysmon-modular tags by behavioral pattern, not semantic intent.

## Detection Opportunities Present in This Data

- **EID 4688 (Security)**: Command line `vaultcmd /listcreds:"Windows Credentials"` under SYSTEM from a PowerShell parent is unambiguous. Any `VaultCmd.exe /listcreds` invocation outside an administrative context should be investigated.
- **EID 1 (Sysmon)**: `VaultCmd.exe` with `CommandLine: vaultcmd /listcreds:"Windows Credentials"` — directly signable.
- **Parent-child chain**: `powershell.exe → cmd.exe → VaultCmd.exe` is an unusual invocation pattern; VaultCmd is rarely run from PowerShell in legitimate administrative workflows.
- **EID 4703**: Token right adjustment under SYSTEM preceding VaultCmd execution places the credential enumeration in the context of an elevated, non-interactive session.
- **Hunting**: VaultCmd.exe appearing in process creation logs on endpoints is low-frequency and worth baselining. Rare use of this binary — especially outside IT management tooling — is a viable detection hypothesis.
