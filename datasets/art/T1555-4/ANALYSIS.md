# T1555-4: Credentials from Password Stores — Enumerate Credentials from Windows Credential Manager Using vaultcmd.exe [Windows Credentials]

## Technique Context

T1555 covers credential theft from password stores. This test uses `vaultcmd.exe`, a legitimate Windows built-in utility, to enumerate the Windows Credentials vault. Unlike the PowerShell-based tests (T1555-2/3), `vaultcmd.exe` is a LOLBin (Living Off the Land Binary) — it is a signed, Microsoft-shipped tool with no offensive reputation, making it less likely to trigger AV detection. The command `vaultcmd /listcreds:"Windows Credentials" /all` outputs credential metadata (account names, types, resource names) but does not decrypt or output plaintext passwords. This technique is often used for reconnaissance to identify which credentials are stored before targeting them with deeper extraction tools.

## What This Dataset Contains

The dataset spans approximately 6 seconds (2026-03-14T00:37:49Z – 00:37:55Z) on ACME-WS02.

**The attack commands are visible in Security EID 4688:**

> `"powershell.exe" & {vaultcmd /listcreds:"Windows Credentials" /all}`
> `"C:\Windows\system32\VaultCmd.exe" "/listcreds:Windows Credentials" /all`

The call chain is PowerShell → VaultCmd.exe. Sysmon EID 1 records both the intermediate PowerShell process and the VaultCmd.exe process create with full command line and parent chain. VaultCmd.exe is tagged by sysmon-modular with `technique_id=T1083,technique_name=File and Directory Discovery`, reflecting the config's classification of vault enumeration.

**No Defender block occurred.** VaultCmd.exe is a signed Windows binary; AMSI does not scan its output, and Defender does not interfere with its execution. The process terminated normally. The exit code is not captured in the Security log for this test run.

The Sysmon dataset contains the expected boilerplate for each PowerShell invocation: DLL image loads (EID 7) for `AMSI.dll`, `clrjit.dll`, and PSReadline modules tagged T1055/T1574.002, plus a named pipe creation (EID 17). Security events are limited to process creation (4688), process termination (4689), and token right adjustment (4703) — confirming that vaultcmd.exe ran without triggering any object access or policy change auditing.

## What This Dataset Does Not Contain (and Why)

**Credential output.** VaultCmd.exe writes its output to stdout; no file write events appear. Console output is not captured in Windows event logs. The dataset demonstrates that enumeration was commanded but does not record what credentials (if any) were listed.

**Success confirmation beyond process exit.** Object access auditing is disabled; no EID 4663 events for reads of the vault file at `%LOCALAPPDATA%\Microsoft\Vault` appear. Whether credentials were present and enumerated is not determinable from this telemetry alone.

**Sysmon EID 22 DNS.** VaultCmd.exe makes no network connections; no DNS events are expected or present.

**Defender interference.** VaultCmd.exe is not flagged by signature-based detection. This is in contrast to T1555-2 and T1555-3 where AMSI blocked the PowerShell scripts. This dataset represents a detection-evasion scenario via LOLBin use.

## Assessment

This dataset captures a **complete, unblocked execution** of vaultcmd.exe for Windows Credential Manager enumeration. The technique succeeded at least up to the vault query stage, though whether any credentials were stored and returned cannot be determined from the available telemetry. This is a genuinely harder-to-detect credential access pattern compared to T1555-2/3: no AMSI block, no malicious PowerShell content, and the binary is Microsoft-signed. Detection depends on behavioral analytics — specifically, detecting vaultcmd.exe executing with `/listcreds` arguments in contexts that are anomalous for the workstation.

## Detection Opportunities Present in This Data

- **Security EID 4688**: Process creation for `VaultCmd.exe` with command line `/listcreds:"Windows Credentials" /all`. The `/listcreds` argument with `/all` is not a routine admin operation on workstations and is a reliable indicator of credential enumeration.
- **Sysmon EID 1**: VaultCmd.exe process create with parent PowerShell process, full command line, and file hash fields (SHA256 available for allowlist/blocklist matching). Tagged T1083 in the current config — a detection opportunity even without a T1555-specific rule.
- **Security EID 4688 (parent)**: `powershell.exe` launched with `vaultcmd /listcreds:"Windows Credentials" /all` in the command line — detectable at the PowerShell layer before the child process is created.
- **PowerShell EID 4104**: The scriptblock `& {vaultcmd /listcreds:"Windows Credentials" /all}` is logged by script block logging, even though it is a native command rather than a PowerShell cmdlet.
- **Process ancestry**: VaultCmd.exe spawned by PowerShell running as SYSTEM is an anomalous parent-child relationship for legitimate vault operations, which would typically originate from user-context GUI interactions.
