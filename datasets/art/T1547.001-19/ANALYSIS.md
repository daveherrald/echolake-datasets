# T1547.001-19: Registry Run Keys / Startup Folder — Creating Boot Verification Program Key for Application Execution During Successful Boot

## Technique Context

MITRE ATT&CK T1547.001 covers persistence through registry run keys and startup mechanisms. The `BootVerificationProgram` key under `HKLM\System\CurrentControlSet\Control\BootVerificationProgram` allows specifying a program that runs after a successful boot to verify system integrity. This key is legitimate but almost never populated in practice — Windows only invokes it when configured, making any presence of an `ImagePath` value here a strong indicator of adversarial activity. The specified program runs with SYSTEM-level privileges early in the boot process. Adversaries use this mechanism to establish persistence that is difficult to attribute to a specific user session and that fires on every boot regardless of which user logs in.

## What This Dataset Contains

This dataset captures telemetry from the Atomic Red Team test that creates the `BootVerificationProgram\ImagePath` value pointing to `C:\Program Files\Internet Explorer\iexplore.exe` using `reg add` via `cmd.exe`.

**Sysmon (28 events):**
- EID 1 (Process Create): `whoami.exe` (test framework identity check). `cmd.exe` spawned by PowerShell with the full command: `"cmd.exe" /c reg add HKLM\System\CurrentControlSet\Control\BootVerificationProgram /v ImagePath /t REG_SZ /d "C:\Program Files\Internet Explorer\iexplore.exe"`. `reg.exe` spawned by `cmd.exe` with the same arguments.
- EID 7 (Image Load): DLL loads for PowerShell — standard .NET runtime behavior.
- EID 10 (Process Access): PowerShell accessing `whoami.exe` with `0x1FFFFF`.
- EID 11 (File Create): PowerShell startup profile data file.
- EID 13 (Registry Value Set): `reg.exe` writing `HKLM\System\CurrentControlSet\Control\BootVerificationProgram\ImagePath` with value `C:\Program Files\Internet Explorer\iexplore.exe`. This event is present but without a T1547.001 Sysmon rule annotation — the sysmon-modular configuration does not include this specific path in its tagged registry rules.
- EID 17 (Pipe Create): Named pipe from PowerShell.

**Security (12 events):**
- EID 4688/4689: Process creates and exits for both PowerShell instances, `whoami.exe`, `cmd.exe`, `reg.exe`, and `conhost.exe`. The 4688 events for `cmd.exe` and `reg.exe` record the full `reg add` command line including the `BootVerificationProgram` path, `ImagePath` value name, and `iexplore.exe` path.
- EID 4703: Token right adjustment for PowerShell.

**PowerShell (35 events):**
- EID 4103: `Set-ExecutionPolicy -Scope Process -Force` (test framework preamble, appears twice).
- EID 4104: All scriptblock events are PowerShell runtime boilerplate. The test action is executed via `cmd.exe /c reg add`, not as a PowerShell cmdlet, so no substantive script block events are generated for the persistence registration.

## What This Dataset Does Not Contain

- No boot-time execution of the registered `iexplore.exe` occurs. The system was not rebooted after test execution; the persistence entry is created but not triggered.
- The Sysmon EID 13 event captures the registry write, but the event lacks a T1547.001 rule annotation — this path is not in the sysmon-modular include list for tagged registry writes.
- No PowerShell EID 4104 events capture the test logic — the action runs via `cmd.exe` shell.
- No network connection events appear in this dataset.
- Windows Defender did not block the registry write.

## Assessment

The test completed successfully. The registry write is captured in Sysmon EID 13 (without a technique annotation) and the process creation events in both Sysmon EID 1 and Security EID 4688 record the full `reg add` command line. The `BootVerificationProgram` key path is distinctive — legitimate software essentially never populates this key, so any write to it is high-confidence suspicious.

The use of `iexplore.exe` as the payload path is transparent in the logs. A real adversary would use a malicious binary, but the key path and value name would be identical. Detection should focus on the key path existence rather than the specific program value.

## Detection Opportunities Present in This Data

- **Sysmon EID 13**: Registry write to `HKLM\System\CurrentControlSet\Control\BootVerificationProgram\ImagePath` is a near-unique indicator. This key is not populated in default Windows installations.
- **Security EID 4688**: `reg.exe` command line containing `BootVerificationProgram` and `ImagePath` — unambiguous in a process creation event.
- **Sysmon EID 1**: `reg.exe` with `BootVerificationProgram` in the command line.
- **Threat hunting**: Querying for any value under `HKLM\System\CurrentControlSet\Control\BootVerificationProgram\` across an estate will identify compromised hosts — this key being present at all is a strong indicator.
- **Gap to note**: Sysmon EID 13 is present for this write, but without a T1547.001 rule annotation. Detection engineering teams using the sysmon-modular configuration should consider adding `BootVerificationProgram` to the registry monitoring ruleset.
