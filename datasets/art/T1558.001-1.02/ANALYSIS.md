# T1558.001-1: Steal or Forge Kerberos Tickets: Golden Ticket — Crafting Active Directory Golden Tickets with Mimikatz

## Technique Context

MITRE ATT&CK T1558.001 (Golden Ticket) is a Kerberos persistence and lateral movement technique where an attacker forges a Ticket Granting Ticket (TGT) using the KRBTGT account's hash. Because the KRBTGT hash is used to sign all TGTs issued by a domain controller, possession of this hash enables creation of arbitrary TGTs for any user or group, valid for any duration. Golden tickets provide domain persistence that survives most account password resets. Mimikatz performs this via its `kerberos::golden` module using either the NTLM hash or AES256 key.

With Defender disabled, Mimikatz can download, load, and execute the `kerberos::golden` function without AMSI interception. The golden ticket attack proceeds: compute a forged TGT, inject it into the current session with `/ptt`, and use it to authenticate to domain resources.

## What This Dataset Contains

This dataset was captured on ACME-WS06 (Windows 11 Enterprise, domain acme.local) on 2026-03-17 with Defender disabled, spanning approximately 2 seconds. It contains 133 events across four channels: 27 Sysmon, 101 PowerShell, 4 Security, and 1 Application.

**Command executed (Security EID=4688):**
The test script constructs a batch file at `$env:TEMP\golden.bat` containing a Mimikatz invocation:
```
C:\AtomicRedTeam\atomics\..\ExternalPayloads\mimikatz\x64\mimikatz.exe
  "kerberos::golden /domain:%userdnsdomain%
   /sid:DOMAIN_SID
   /aes256:b7268361386090314acce8d9367e55f55865e7ef8e670fbe4262d6c94098a9e9
   /user:goldenticketfakeuser /ptt" "exit"
```
The full PowerShell script block appears in Security EID=4688 as the command line for the child PowerShell process. The AES256 key `b7268361386090314acce8d9367e55f55865e7ef8e670fbe4262d6c94098a9e9` is the test KRBTGT hash used by this ART test. The username `goldenticketfakeuser` identifies this as a golden ticket for a non-existent user.

**PowerShell EID=4104:** 97 script block events. With Defender disabled, the full golden ticket construction script is evaluated and logged — including the Mimikatz invocation string, the AES256 key, the target username, and the batch file construction logic. This content was entirely absent in the defended dataset.

**Sysmon EID=8 (CreateRemoteThread):** One EID=8 event showing `powershell.exe` (PID 17692) creating a remote thread in `<unknown process>` (PID 17308), tagged `technique_id=T1055,technique_name=Process Injection`. StartAddress: `0x00007FF658E64EB0`. The same StartAddress appears in T1555.004-2 and T1558.002-1 — this is a characteristic address associated with Mimikatz or WinPwn's in-memory loading mechanism.

**Sysmon EID=10 (Process Access):** Three EID=10 events at `GrantedAccess: 0x1FFFFF`, tagged `T1055.001`.

**Sysmon EID=1 (Process Create):** Three process creations: `whoami.exe` (tagged T1033) and the child PowerShell executing the golden ticket script (tagged T1059.001).

**Sysmon EID=11 (File Created):** One EID=11 event showing `C:\Windows\Temp\01dcb633071a6df7` created by `MsMpEng.exe` — a Defender scan artifact generated even with real-time protection disabled (passive-mode scanning). No `golden.bat` file creation appears in the Sysmon sample set, though the script creates it at `%TEMP%`.

**Security EID=4688:** Four process creation events (SYSTEM context) capturing the golden ticket script as the PowerShell command line.

## What This Dataset Does Not Contain

**Mimikatz process creation in Sysmon EID=1.** The Mimikatz binary (`mimikatz.exe`) is launched from a batch file via `runas /netonly`. In the short dataset window, the batch file execution and Mimikatz invocation may have occurred but the specific Sysmon EID=1 for mimikatz.exe is not present in the sample set. The batch file construction approach (writing to `golden.bat`, then using `runas /netonly /user:fake`) is designed to create a separate logon session so that the forged ticket does not contaminate the current session.

**Kerberos TGT events (EID=4768/4769) on the domain controller.** Golden ticket forging occurs entirely on the client using the supplied KRBTGT hash — no request is sent to the domain controller during forging. Even in a successful execution, DC-side Kerberos events would only appear if the forged ticket were subsequently used to authenticate to a service.

**Security EID=4624 (Logon) for the runas /netonly session.** Unlike the Rubeus variant (T1558.001-2), no logon event appears in this dataset for the new session created by `runas /netonly`. This may reflect the batch file execution timing being outside the capture window.

**Comparison with the defended variant:** In the defended dataset (sysmon: 17, security: 9, powershell: 34), AMSI blocked the Mimikatz payload before it could execute — the PowerShell event count was 34 (mostly boilerplate). Here, 101 events appear, including the full golden ticket construction script with the AES256 key and the Mimikatz invocation string. The Sysmon EID=8 (CreateRemoteThread) appears in both datasets, confirming this injection pattern fires during the loading phase, regardless of whether AMSI subsequently blocks the payload.

## Assessment

This dataset provides a significantly richer view of the golden ticket attempt than the defended variant. The PowerShell EID=4104 events preserve the complete `kerberos::golden` invocation string including the test AES256 KRBTGT hash, the fake username `goldenticketfakeuser`, the `/ptt` flag, and the batch file construction logic. These details were entirely absent when Defender was active.

The Sysmon EID=8 (CreateRemoteThread to `<unknown process>`) at `0x00007FF658E64EB0` is the most reliable cross-test Mimikatz/WinPwn behavioral indicator in this dataset series — the same StartAddress appears across multiple tests, suggesting it represents a common in-memory loading mechanism used by these tools.

## Detection Opportunities Present in This Data

**PowerShell EID=4104 — kerberos::golden invocation string:** The string `kerberos::golden /domain:` combined with `/aes256:` or `/ntlm:` and `/user:` in a PowerShell script block is a precise Mimikatz golden ticket indicator.

**PowerShell EID=4104 — AES256 KRBTGT hash:** The 64-character hex string `b7268361386090314acce8d9367e55f55865e7ef8e670fbe4262d6c94098a9e9` is the test KRBTGT key used by ART. In real environments, detecting any AES256 key in the context of a Kerberos forging invocation is the relevant pattern.

**PowerShell EID=4104 — Mimikatz binary path in ExternalPayloads:** The path `C:\AtomicRedTeam\atomics\..\ExternalPayloads\mimikatz\x64\mimikatz.exe` is ART-specific, but monitoring for `mimikatz.exe` references in any PowerShell script block provides broad coverage.

**Sysmon EID=8 — CreateRemoteThread from PowerShell to unknown process:** The specific StartAddress `0x00007FF658E64EB0` combined with process injection tagging from a PowerShell source process is a high-fidelity behavioral indicator for Mimikatz and related tools.

**Security EID=4688 — PowerShell command line with Mimikatz batch construction pattern:** The combination of `golden.bat`, `runas /netonly /user:fake`, and a Mimikatz invocation in the script block is a recognizable attack pattern for golden ticket attacks using the batch-file isolation technique.
