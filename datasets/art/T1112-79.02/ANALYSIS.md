# T1112-79: Modify Registry — Modify UseTPMPIN Registry Entry

## Technique Context

T1112 (Modify Registry) is used here to modify the `UseTPMPIN` value in `HKLM\SOFTWARE\Policies\Microsoft\FVE` (Full Volume Encryption). The FVE policy key governs BitLocker behavior on Windows systems. The `UseTPMPIN` value controls whether BitLocker requires a PIN in addition to the TPM chip during boot. Setting it to `2` means "Allow TPM+PIN"—changing the policy from a more restrictive setting (such as `1` = Require TPM only, or a Group Policy-enforced value) to one that permits the user to configure a PIN or not.

Adversaries who have achieved SYSTEM-level access on a BitLocker-protected system may modify FVE policy values to weaken disk encryption requirements. In a ransomware scenario, weakening BitLocker can facilitate physical access to encrypted volumes or simplify the process of staging the ransomware binary on the drive. More broadly, any modification to FVE policy values by non-administrative tooling (i.e., not Group Policy) is anomalous: these values should only change through managed Group Policy updates, not through direct registry writes from `reg.exe`.

This test is closely related to T1112-81 (`UseTPMKeyPIN`) and T1112-83 (`UsePartialEncryptionKey`), which modify different FVE policy values. Together they represent a pattern of targeted BitLocker policy weakening.

## What This Dataset Contains

This dataset captures the `UseTPMPIN` registry modification on a Windows 11 Enterprise domain workstation with Defender disabled. Events occur at approximately 2026-03-17T16:35:17Z, in the same session as T1112-74, T1112-75, T1112-81, and T1112-83.

The attack chain is PowerShell (SYSTEM) → cmd.exe → reg.exe. Sysmon EID 1 captures both child processes:

- `cmd.exe` (PID 17148, ProcessGuid `{9dc7570a-82c5-69b9-de39-000000000900}`, RuleName `technique_id=T1059.003`) with command line: `"cmd.exe" /c reg add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v UseTPMPIN /t REG_DWORD /d 2 /f`
- `reg.exe` (PID 16888, ProcessGuid `{9dc7570a-82c5-69b9-e039-000000000900}`, RuleName `technique_id=T1012`) with command line: `reg  add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v UseTPMPIN /t REG_DWORD /d 2 /f`

Both run from `C:\Windows\TEMP\` as `NT AUTHORITY\SYSTEM` at `LogonId: 0x3E7`. Security EID 4688 independently confirms the same process creations.

The Sysmon EID breakdown (7: 9, 1: 4, 10: 3, 17: 1) is consistent with the other tests in this cluster. The PowerShell channel contains 46 EID 4104 events including the cleanup wrapper `Invoke-AtomicTest T1112 -TestNumbers 79 -Cleanup`.

The elevated PowerShell count (46 vs. the 35-36 baseline in neighboring tests) likely reflects additional script block fragments generated during the execution of this test compared to others, possibly due to module initialization overhead when the FVE-related Atomic test is loaded.

## What This Dataset Does Not Contain

No BitLocker status events, TPM event log entries, or `manage-bde.exe` activity appears. The test modifies the policy value in isolation; no BitLocker re-initialization or PIN prompt changes occur within the captured window.

Security EID 4657/4663 events are absent—no SACL on the FVE key. The EID 13 event is in the full dataset but not in the sample subset.

The FVE key may not exist by default on systems where BitLocker has not been configured. In that case, this write creates both the key and the value. The sample data does not differentiate between a write to an existing key versus a key creation, but the Sysmon EID 12 (registry key create) event would capture a key creation if it occurred.

## Assessment

The undefended dataset (Sysmon: 17, Security: 4, PowerShell: 46) versus the defended variant (Sysmon: 22, Security: 13, PowerShell: 34) shows a moderate Sysmon reduction (22 → 17) and the expected Security reduction (13 → 4). The Sysmon differential is smaller here than in T1112-75, suggesting Defender monitors FVE key modifications with slightly less intensity than `Policies\System` changes.

The PowerShell inversion (defended: 34, undefended: 46) continues the pattern seen in other tests: the undefended session sometimes generates more PowerShell events because AMSI interception is absent, allowing more script blocks to execute and log to completion.

The core technique evidence—the full command line writing `UseTPMPIN=2` to the FVE key—is equally present and legible in both variants.

## Detection Opportunities Present in This Data

**Process creation command line (Sysmon EID 1 / Security EID 4688):** The command line `reg add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v UseTPMPIN /t REG_DWORD /d 2 /f` is fully captured. Any `reg.exe` write to the FVE policy path is anomalous in an environment where BitLocker settings are managed through Group Policy.

**FVE key namespace (Sysmon EID 13):** The full dataset contains the direct registry write. Monitoring `HKLM\SOFTWARE\Policies\Microsoft\FVE` for writes from non-Group Policy processes covers `UseTPMPIN`, `UseTPMKeyPIN`, and `UsePartialEncryptionKey` with a single rule.

**Cluster correlation:** This test ran in the same session as T1112-81 and T1112-83, which also target the FVE key with different values. In a real intrusion, three writes to `HKLM\SOFTWARE\Policies\Microsoft\FVE` within a short window—each from the same PowerShell → cmd.exe → reg.exe chain—would be a high-confidence signal of deliberate BitLocker policy weakening.

**Process ancestry from TEMP (Sysmon EID 1):** The consistent `reg.exe` from `C:\Windows\TEMP\` via PowerShell → cmd.exe at SYSTEM integrity is the shared process ancestry indicator across this cluster.
