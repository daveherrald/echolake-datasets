# T1531-2: Account Access Removal — Delete User (Windows)

## Technique Context

T1531 (Account Access Removal) in its delete-user form is used by adversaries to permanently eliminate user accounts, removing access for both the legitimate owner and potentially hindering forensic investigation by destroying account artifacts. Ransomware operators and destructive actors use local account deletion as a disruption step, particularly targeting accounts that might be used for recovery. Detection focuses on `net user /delete` command-line patterns and — in well-configured environments — Security Event ID 4726 (user account deleted).

## What This Dataset Contains

The test creates a temporary local account and then deletes it using a `cmd.exe` compound command driven from `powershell.exe`:

```
"cmd.exe" /c net user AtomicUser User2DeletePW! /add & net.exe user AtomicUser /delete
```

The resulting process chain is `powershell.exe` → `cmd.exe` → `net.exe` → `net1.exe`, appearing twice in sequence — once for `/add` and once for `/delete`. Security 4688 events capture the full command lines for each stage. All `net.exe` and `net1.exe` processes exited `0x0`, confirming both the creation and deletion succeeded. Sysmon Event ID 1 records the same chain with parent-child relationships and process GUIDs for correlation.

The Security channel contains 4688/4689 pairs for each process, plus a 4703 (token right adjusted), but no account management events — account management auditing is not enabled.

The PowerShell channel contains only test framework boilerplate: `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass` (4103) and `Set-StrictMode` fragments (4104). No technique-specific PowerShell content is present.

## What This Dataset Does Not Contain

**No account management events.** With `account_management: none` in the audit policy, Event IDs 4720 (account created), 4726 (account deleted), and 4738 (account changed) do not appear. The deletion is confirmed only by `net1.exe` exiting `0x0` with `/delete` in its command line — not by a dedicated account-state event. In a production environment with Account Management auditing enabled, 4726 would be the definitive indicator.

**No SAM-level registry activity** capturing the account removal from the local security database.

## Assessment

This dataset provides good command-line evidence for the account-deletion pattern. The `/delete` flag appears unambiguously in Security 4688 and Sysmon Event ID 1. The compound command structure (`/add` followed by `/delete` in one `cmd.exe` invocation) is realistic of tooling that creates and tears down test accounts in cleanup logic. The dataset honestly represents the detection gap created by absent account management auditing. A companion dataset with Account Management auditing enabled would show 4726 and make this a complete coverage example.

## Detection Opportunities Present in This Data

1. **Security 4688**: `net.exe` process created with command line matching `user .* /delete` — primary indicator of local account deletion.
2. **Sysmon Event ID 1**: `net.exe` with CommandLine containing `user <username> /delete`, parent `cmd.exe` — process chain detection.
3. **Sysmon Event ID 1**: `net1.exe` spawned by `net.exe` with `/delete` in parent command line — child process confirmation.
4. **Security 4688**: `cmd.exe` launched from `powershell.exe` with compound command containing `net user` and `/delete` — scripted deletion pattern.
5. **Security 4689**: `net1.exe` exiting `0x0` after a `/delete` invocation — outcome confirmation for behavioral baselines.
6. **Sequence correlation**: `net user <account> <password> /add` followed within seconds by `net user <account> /delete` from the same parent process — test-and-cleanup or create-and-remove account lifecycle pattern indicative of adversarial staging.
