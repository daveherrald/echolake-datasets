# T1112-8: Modify Registry — BlackByte Ransomware Registry Changes (CMD)

## Technique Context

T1112 (Modify Registry) is used here to replicate the pre-encryption registry modification behavior of the BlackByte ransomware family. BlackByte makes three specific registry changes before deploying its encryption payload, all using `cmd.exe` with chained `reg.exe` invocations:

1. `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy = 1` — disables UAC remote restrictions, allowing local administrator accounts to authenticate over the network with full administrator tokens (enabling lateral movement via pass-the-hash and SMB admin shares).
2. `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLinkedConnections = 1` — enables linked connections so that elevated processes and standard user processes share mapped network drives (facilitating access to network shares during encryption).
3. `HKLM\SYSTEM\CurrentControlSet\Control\FileSystem\LongPathsEnabled = 1` — enables long path support, allowing BlackByte to access and encrypt files with paths exceeding the traditional 260-character MAX_PATH limit.

These three changes work together: the first two expand the attacker's network reach and privilege scope; the third ensures no file is inaccessible due to path length restrictions. This combination is a documented BlackByte operational signature and a reliable indicator of ransomware pre-staging.

## What This Dataset Contains

This dataset captures all three BlackByte registry modifications in a single execution on a Windows 11 Enterprise domain workstation with Defender disabled. Events occur at approximately 2026-03-17T16:35:25Z to 16:35:31Z.

The execution structure differs from other T1112 tests in this batch. The parent cmd.exe (PID 14744, ProcessGuid `{9dc7570a-82d0-69b9-ed39-000000000900}`) chains all three modifications in a single command line using `&` separators:

```
"cmd.exe" /c cmd.exe /c reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f & cmd.exe /c reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLinkedConnections /t REG_DWORD /d 1 /f & cmd.exe /c reg add HKLM\SYSTEM\CurrentControlSet\Control\FileSystem /v LongPathsEnabled /t REG_DWORD /d 1 /f
```

This creates a command-within-command structure: an outer cmd.exe spawns three inner cmd.exe processes, each invoking `reg.exe` for one registry change. The Sysmon EID breakdown (7: 9, 1: 9, 10: 3, 3: 3, 13: 2, 17: 1) reflects this multiplied process creation: 9 EID 1 events cover the outer cmd.exe, three inner cmd.exe processes, three reg.exe processes, plus `whoami.exe` (x2 for pre/post execution checks). Two EID 13 events capture two of the three registry writes (one per value, with the third either in non-sampled data or merged).

The first inner cmd.exe (PID 15720, RuleName `technique_id=T1059.003`) is captured with command line: `cmd.exe  /c reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f`

Three Sysmon EID 3 (network connection) events capture MsMpEng.exe (Windows Defender engine process, PID 3556) making outbound TCP connections to `48.211.71.194:443`. These connections occur because Defender's engine process is active (it is installed even though real-time protection is disabled) and periodically connects to Microsoft cloud services for signature updates. The destination IP belongs to Microsoft's cloud infrastructure.

Security EID 4688 records 9 process creation events covering the full chain. PowerShell channel contains 97 EID 4104 events—the same elevated count seen in T1112-74—reflecting the larger session context on March 17.

## What This Dataset Does Not Contain

The full set of three reg.exe invocations is not fully represented in the sample subset, but all three are present in the complete dataset. The chained command structure means some processes appear in the breakdown count but not in the sample window shown.

No evidence of subsequent lateral movement, SMB access using the newly enabled `LocalAccountTokenFilterPolicy`, or network share traversal appears. These changes set up the preconditions for BlackByte's encryption phase but the actual encryption step is not part of this test.

No Sysmon EID 12 (registry key create) events appear for the `Policies\System` modifications—these keys already exist. The `Control\FileSystem` key also pre-exists on Windows 11.

## Assessment

The undefended dataset (Sysmon: 27, Security: 9, PowerShell: 97) compared to the defended variant (Sysmon: 29, Security: 22, PowerShell: 34) shows a smaller Sysmon differential than expected (29 → 27) but a large Security channel reduction (22 → 9). The defended dataset's high Security count reflects Defender's aggressive monitoring of `Policies\System` key modifications and the UAC policy change specifically. The smaller Sysmon differential is consistent with the multiplied process creation from the chained cmd.exe invocations: even without Defender, the test inherently generates more events than single-step tests.

This test generates the most complex process tree in the batch—the outer cmd.exe → inner cmd.exe → reg.exe chain is structurally more detectable than a simple PowerShell → cmd.exe → reg.exe path because the nesting is itself suspicious. Legitimate administrative `reg.exe` invocations do not typically appear as grandchildren of a PowerShell process via a double cmd.exe shell.

## Detection Opportunities Present in This Data

**Chained command line (Sysmon EID 1 / Security EID 4688):** The outer cmd.exe command line contains all three registry targets in a single string, making it possible to detect the full BlackByte registry staging pattern from a single event. The `LocalAccountTokenFilterPolicy` value name is a well-known indicator on its own; its presence alongside `EnableLinkedConnections` and `LongPathsEnabled` in the same command line is a high-confidence BlackByte signature.

**Three writes to `Policies\System` and `FileSystem` (Sysmon EID 13):** The full dataset contains direct registry write events for the targeted values. Monitoring `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy` set to `1` is a standalone detection regardless of the writing mechanism.

**Double cmd.exe nesting (Sysmon EID 1):** `cmd.exe /c cmd.exe /c reg add ...` is a process tree pattern that does not occur in legitimate administration. The double-shell nesting is directly visible in the command-line arguments and provides a high-specificity structural indicator.

**MsMpEng.exe network connections (Sysmon EID 3):** The three EID 3 events showing Defender's engine process connecting to `48.211.71.194:443` are background activity—but their presence in the dataset is useful for establishing that Defender was running (though not protecting) during this test, confirming the undefended label is accurate.

**Temporal cluster (Sysmon EID 1):** All three registry modifications complete within approximately 2.6 seconds (16:35:28.837 to 16:35:31.451). Three rapid successive writes to security-policy keys from the same process ancestry is a burst pattern worth alerting on independently of the specific keys involved.
