# T1555-5: Credentials from Password Stores — Enumerate Credentials from Windows Credential Manager Using vaultcmd.exe [Web Credentials]

## Technique Context

T1555 covers credential theft from password stores. This test mirrors T1555-4 but targets the Web Credentials vault rather than the Windows Credentials vault. The command `vaultcmd /listcreds:"Web Credentials" /all` enumerates credentials stored by Internet Explorer and legacy Microsoft Edge, including site URLs, account names, and credential types. Like T1555-4, this uses `vaultcmd.exe` — a Microsoft-signed LOLBin — to avoid AV and AMSI detection. In the real-world attack pattern, both vaults are typically enumerated in sequence, with results used to identify high-value credentials for deeper DPAPI-based decryption.

## What This Dataset Contains

The dataset spans approximately 6 seconds (2026-03-14T00:38:05Z – 00:38:11Z) on ACME-WS02.

**The attack commands are visible in Security EID 4688 and Sysmon EID 1:**

> `"powershell.exe" & {vaultcmd /listcreds:"Web Credentials" /all}`
> `"C:\Windows\system32\VaultCmd.exe" "/listcreds:Web Credentials" /all`

The telemetry structure is identical to T1555-4: PowerShell parent process, VaultCmd.exe child process with the `/listcreds:"Web Credentials" /all` arguments fully recorded, and the same set of Sysmon EID 7 DLL load events, EID 17 pipe creation, and Security EID 4688/4689/4703 process lifecycle events. Sysmon EID 1 tags VaultCmd.exe with `technique_id=T1083,technique_name=File and Directory Discovery`.

**No Defender block occurred.** VaultCmd.exe executed without interference, identical to T1555-4.

The dataset includes 42 Sysmon events and 12 Security events. The higher Sysmon event count compared to T1555-4 (38 events) reflects the standard variation in PowerShell startup DLL load events between sessions.

## What This Dataset Does Not Contain (and Why)

**Credential output from the Web Credentials vault.** Console output from VaultCmd.exe is not logged. On a freshly provisioned workstation like ACME-WS02 that has not had a user browsing session with credential saving enabled, the Web Credentials vault is likely empty — but this cannot be confirmed from the available telemetry.

**Differentiation from T1555-4 beyond the vault name.** The telemetry pattern is structurally indistinguishable from T1555-4 except for the command-line argument `"Web Credentials"` vs `"Windows Credentials"`. Detection rules written for T1555-4 will cover T1555-5 as well, with the vault name differentiating the specific target.

**Object access events.** Object access auditing is not enabled; reads of `%APPDATA%\Microsoft\Vault\*` (the Web Credentials vault location) are not recorded.

## Assessment

This dataset is the Web Credentials counterpart to T1555-4. Both tests represent **unblocked LOLBin execution** for vault enumeration. The only forensic differentiator is the vault name in the command line argument. The two tests together illustrate the systematic enumeration pattern common in real intrusions: an attacker running both `vaultcmd /listcreds:"Windows Credentials" /all` and `vaultcmd /listcreds:"Web Credentials" /all` within seconds on the same host. Detection content should handle both vaults and, ideally, flag the combination as a higher-confidence indicator.

## Detection Opportunities Present in This Data

- **Security EID 4688**: `VaultCmd.exe` with `/listcreds:"Web Credentials" /all` — the vault name argument directly identifies the target store.
- **Sysmon EID 1**: Full command line, file hashes, and parent process chain for VaultCmd.exe. Tagged T1083; a T1555-specific rule is not present in the current sysmon-modular config.
- **PowerShell EID 4104**: Scriptblock `& {vaultcmd /listcreds:"Web Credentials" /all}` visible in script block logging.
- **Temporal correlation with T1555-4**: VaultCmd.exe with "Windows Credentials" (T1555-4, 00:37:54) followed 16 seconds later by VaultCmd.exe with "Web Credentials" (T1555-5, 00:38:10) on the same host — the sequential pattern matches systematic vault enumeration by an automated tool or attacker systematically iterating credential stores.
- **Process context anomaly**: VaultCmd.exe launched by a SYSTEM-context PowerShell process on a workstation is abnormal. Legitimate vault operations from the user's perspective originate from user-context GUI processes, not SYSTEM-context automation.
