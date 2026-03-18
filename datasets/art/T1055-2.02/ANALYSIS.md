# T1055-2: Process Injection — Remote Process Injection in LSASS via mimikatz

## Technique Context

T1055 Process Injection covers adversary code execution within another process's memory space. LSASS (`lsass.exe`, the Local Security Authority Subsystem Service) is among the highest-value injection targets on a Windows system. LSASS handles authentication, stores credential material (NTLM hashes, Kerberos tickets, cached credentials), and runs with SYSTEM privileges. Injecting into LSASS provides both access to credential material and a highly-privileged execution context that is difficult to terminate without destabilizing the operating system.

This specific test chains several attack techniques: it uses `PsExec.exe` to elevate to SYSTEM on a remote host, then runs `mimikatz.exe` with the `lsadump::lsa /inject /id:500` command against a domain controller (`DC1`). This is an advanced lateral movement and credential theft scenario — not just injecting into the local LSASS but targeting the DC's LSASS remotely through PsExec. The combination exposes domain-level secrets including the KRBTGT hash (enabling Golden Ticket attacks) and all domain account NTLM hashes. `lsadump::lsa /inject /id:500` specifically targets the built-in Administrator account (RID 500).

Detection for LSASS injection is well-studied. Sysmon EID 10 with `TargetImage: lsass.exe` and high-privilege access masks, Sysmon EID 8 (CreateRemoteThread into lsass.exe), Windows Defender Credential Guard alerts, and the Windows event ID for LSASS access (EID 4656, 4663) are all established detection points. The challenge is that LSASS is legitimately accessed by many system processes, requiring careful access-mask and caller filtering.

## What This Dataset Contains

With Defender disabled, mimikatz can execute without being blocked at the binary level. The dataset captures the execution attempt and a critical injection activity indicator.

**Security EID 4688 — process creation (4 events):** Two pairs document the test. The key command line is fully preserved:

```
"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\PsExec.exe" /accepteula \\DC1 -c %tmp%\mimikatz\x64\mimikatz.exe "lsadump::lsa /inject /id:500" "exit"
```

This command uses PsExec to copy mimikatz to `\\DC1` and execute it there with the LSA dump command. The `/accepteula` flag suppresses the EULA dialog. The `%tmp%\mimikatz\x64\mimikatz.exe` path indicates mimikatz was pre-staged in the temp directory. A second `cmd.exe` with an empty command line appears as cleanup.

**Sysmon EID 8 — CreateRemoteThread (1 event):** This is the most significant event in the dataset. PowerShell (PID 5436) creates a remote thread in an `<unknown process>` (PID 4780) with:
- `StartAddress: 0x00007FF7F015F8F0`
- Rule: `technique_id=T1055,technique_name=Process Injection`

The target process shows as `<unknown process>` rather than a named process. This can occur when the target process has already exited or when access to the process object was restricted at the time of event generation. The specific `StartAddress` value falls in a range consistent with a user-mode executable rather than a system DLL.

**Sysmon EID 10 — process access (3 events):** PowerShell (PID 5436) accessing `whoami.exe` (PID 6232 and 2384) with `GrantedAccess: 0x1fffff`. These are test framework artifacts, not LSASS access events.

**Sysmon EID 1 — process create (3 events):** `whoami.exe` twice and a cleanup `cmd.exe`.

**Sysmon EID 7 — image load (8 events):** .NET CLR and Defender DLLs in PowerShell processes.

**Sysmon EID 17 — named pipe create (1 event):** PowerShell host pipe.

**Sysmon EID 2 — file creation time changed (1 event):** Possibly reflecting Defender scan activity on mimikatz binary.

**PowerShell EID 4104 (93), EID 4100 (2), EID 4103 (1):** Test framework boilerplate plus two EID 4100 pipeline error events, which indicate something in the PowerShell pipeline failed.

**Comparison to defended dataset:** The defended version recorded 25 sysmon, 9 security, and 41 powershell events. The undefended dataset is slightly smaller: 17 sysmon, 4 security, 96 powershell events. This counter-intuitive reduction may reflect that the defended run generated additional Defender-related process activity. The critical difference is the presence of Sysmon EID 8 in the undefended dataset — a CreateRemoteThread event that does not appear in the defended version (where Defender likely blocked mimikatz before it reached the injection phase).

## What This Dataset Does Not Contain

The remote execution against `\\DC1` means most of the attack's artifacts would appear on the DC, not on the source workstation captured here. This dataset documents the initiating workstation's perspective only:

- No Sysmon EID 1 for PsExec.exe or mimikatz.exe. PsExec is a child of `cmd.exe` and doesn't match include-mode filters; mimikatz runs on the DC, not locally.
- No LSASS process access events (Sysmon EID 10 with `TargetImage: lsass.exe`). The lsadump operation targets the DC's LSASS, not the local system.
- No credential material in the event data. Successful `lsadump::lsa` output would appear in PsExec's console output on the DC, not in the source workstation's logs.
- No network connection events (Sysmon EID 3) showing PsExec's SMB connection to DC1. Network monitoring is enabled but may have missed the brief SMB session, or the DC was unreachable.
- No EID 4656/4663 (object access) for LSASS. Object access auditing is not enabled in this configuration.

## Assessment

This dataset provides limited but important signal. The Security EID 4688 command line fully documents the attack intent: remote PsExec execution of mimikatz with a specific LSASS dump argument against a named domain controller. The Sysmon EID 8 CreateRemoteThread event adds a behavioral injection indicator, though the target process is unresolved (`<unknown process>`). For defenders building detections against this scenario, the workstation-side telemetry would alert on the PsExec command line while the DC's own logs would capture the LSASS access. This dataset covers the workstation side only.

The dataset is valuable for testing command-line detections against mimikatz argument patterns and PsExec-to-DC lateral movement indicators.

## Detection Opportunities Present in This Data

1. Security EID 4688 `CommandLine` contains `mimikatz.exe` and `lsadump::lsa /inject /id:500` — the mimikatz command is completely exposed in the process creation record.

2. `PsExec.exe /accepteula \\DC1 -c` is a high-confidence lateral movement indicator; the `-c` flag (copy binary to remote) combined with a domain controller target name is particularly suspicious.

3. Sysmon EID 8 (CreateRemoteThread) from PowerShell to `<unknown process>` with a user-space `StartAddress` — even without a resolved target process name, an EID 8 from a PowerShell process warrants investigation.

4. The `%tmp%\mimikatz\x64\mimikatz.exe` path suggests pre-staging in the user temp directory. EID 4688 or Sysmon EID 1 events for executables in `%TEMP%\mimikatz\` are direct IOC-level matches.

5. The combination of `PsExec.exe` with `-c` (binary copy) targeting a specific hostname followed by known credential-dumping tool arguments in a single `cmd.exe` command is a specific and detectable attack sequence.

6. Sysmon EID 2 (file creation time changed) on a mimikatz binary (detectable by hash or by path pattern) from `MsMpEng.exe` can indicate that Defender scanned the file even when real-time protection is disabled — useful for confirming binary presence on the filesystem.
