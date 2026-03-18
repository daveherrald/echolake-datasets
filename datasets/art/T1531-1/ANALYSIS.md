# T1531-1: Account Access Removal — Change User Password (Windows)

## Technique Context

T1531 (Account Access Removal) is an Impact-tactic technique used by adversaries to lock out legitimate users from their accounts, forcing disruption to operations or as a counter-forensics measure against incident responders. On Windows, the most straightforward form is resetting a local user's password with `net user`. Threat actors — including ransomware operators and destructive threat groups — use this just before deploying a payload to prevent defenders from logging back in. Detection engineering typically targets `net user <account> <password>` command-line patterns, the `net.exe` → `net1.exe` spawn chain, and Windows account management events such as 4723 (password change attempt) and 4724 (admin password reset), provided account management auditing is enabled.

## What This Dataset Contains

The test creates a local account and then changes its password using a single `cmd.exe` compound command launched from `powershell.exe`:

```
"cmd.exe" /c net user AtomicAdministrator User2ChangePW! /add & net.exe user AtomicAdministrator HuHuHUHoHo283283@dJD
```

This produces a well-documented process chain: `powershell.exe` → `cmd.exe` → `net.exe` → `net1.exe`, appearing twice — once for the `/add` and once for the password change. Security 4688 events capture the full command line for each step including both passwords in plaintext. Sysmon Event ID 1 (ProcessCreate) confirms the same chain with parent/child relationships; `net.exe` and `net1.exe` both carry the RuleName `technique_id=T1018` (a sysmon-modular tagging artifact). Both `net1.exe` processes exited with status `0x0`, confirming the operations succeeded. The two initial `cmd.exe` processes that exited with `0x1` are unrelated pre-test framework overhead.

The Security channel also contains a 4624 (Type 5 service logon), 4672 (special privileges for SYSTEM), and 4703 (token right adjusted), all attributable to the SYSTEM execution context, plus a 6416 (new external device) triggered by the print spooler — all OS noise.

The PowerShell channel contains only test framework boilerplate: two rounds of `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass` (Event ID 4103) and internal `Set-StrictMode` script block fragments (Event ID 4104). No technique-specific PowerShell content appears here.

## What This Dataset Does Not Contain

**No account management events.** The audit policy sets `account_management: none`, so Event IDs 4720 (user account created), 4722 (user account enabled), 4724 (admin password reset), and 4738 (user account changed) are absent. These would be the highest-fidelity indicators for this technique in a well-configured environment. For production detections targeting password resets, enabling the Account Management audit subcategory is necessary to surface these events.

**No Sysmon registry writes for the SAM database.** Direct SAM modifications that would accompany local account creation are not captured here.

## Assessment

This dataset is excellent for command-line–based detection engineering. The full `net user` command lines — including the username and both plaintext passwords — appear in both Sysmon Event ID 1 and Security Event ID 4688. The `net.exe` → `net1.exe` process chain is faithfully represented. Because account management auditing is disabled, the dataset reflects a realistic gap that many enterprise environments share: command-line evidence is present but account-state-change confirmation events are absent. Adding the Account Management audit subcategory would significantly strengthen coverage.

## Detection Opportunities Present in This Data

1. **Security 4688**: `net.exe` process created with command line matching `user .* /add` — captures account creation with credential in plaintext.
2. **Security 4688**: `net.exe` or `net1.exe` process created with command line matching `user <username> <string>` without `/add` or `/delete` — password change pattern.
3. **Sysmon Event ID 1**: `net.exe` spawned by `cmd.exe` spawned by `powershell.exe` with `user` in CommandLine — compound command pattern typical of scripted account manipulation.
4. **Sysmon Event ID 1**: `net1.exe` spawned by `net.exe` — confirms legitimate `net.exe` usage vs. direct `net1.exe` invocation masquerade.
5. **Security 4688**: `cmd.exe` launched from `powershell.exe` with a compound (`&`-chained) command line containing `net user` — wrapping pattern common in automated tooling.
6. **Process exit codes in Security 4689**: `net1.exe` exiting `0x0` after a `user <account> <value>` command — confirms the password change succeeded rather than merely attempted.
