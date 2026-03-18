# T1547.001-19: Registry Run Keys / Startup Folder — Creating Boot Verification Program Key for Application Execution During Successful Boot

## Technique Context

T1547.001 covers persistence and privilege escalation through Windows registry run keys and startup mechanisms. This test targets `HKLM\System\CurrentControlSet\Control\BootVerificationProgram`, a registry key that allows specifying a custom program to run after a successful boot to verify system integrity. This mechanism is part of the Windows boot verification subsystem and is intended for authorized diagnostic tools. In practice, this key is almost never populated on production systems — finding an `ImagePath` value here is a near-certain indicator of adversarial activity.

The specified program runs with SYSTEM-level privileges during early boot, before standard user sessions are established, and fires on every successful boot regardless of which user is logged in (or whether any user logs in at all). Adversaries use this mechanism for durable persistence that is invisible to run key monitoring and is not cleaned up by standard profile or session removal.

This dataset was collected on ACME-WS06 (Windows 11 Enterprise Evaluation, domain `acme.local`) with Windows Defender fully disabled via Group Policy. Compare with the defended variant in `datasets/art/T1547.001-19` for the same test against an active Defender installation.

## What This Dataset Contains

The test executed as `NT AUTHORITY\SYSTEM` via QEMU guest agent. A `cmd.exe` process runs `reg add HKLM\System\CurrentControlSet\Control\BootVerificationProgram /v ImagePath /t REG_SZ /d "C:\Program Files\Internet Explorer\iexplore.exe"` to register the persistence entry, followed by cleanup via `reg delete`.

**Sysmon (23 events — EIDs 1, 7, 10, 13, 17):**

EID 1 (ProcessCreate) captures six processes:
- `WmiPrvSE.exe` (tagged T1047) — `C:\Windows\system32\wbem\wmiprvse.exe -Embedding` — a WMI provider host instance spawned as background OS activity, unrelated to the test
- `whoami.exe` (test framework identity check, tagged T1033)
- `cmd.exe` (tagged T1083) with command line: `"cmd.exe" /c reg add HKLM\System\CurrentControlSet\Control\BootVerificationProgram /v ImagePath /t REG_SZ /d "C:\Program Files\Internet Explorer\iexplore.exe"`
- `reg.exe` (tagged T1083) with arguments for the `BootVerificationProgram` key
- A second `whoami.exe` at cleanup
- `cmd.exe` for cleanup: `"cmd.exe" /c reg delete HKLM\System\CurrentControlSet\Control\BootVerificationProgram /f`
- `reg.exe` for the cleanup delete

EID 13 (RegistrySetValue) captures one event from `reg.exe` writing `HKLM\System\CurrentControlSet\Control\BootVerificationProgram\ImagePath` with value `C:\Program Files\Internet Explorer\iexplore.exe`. Notably, this EID 13 event does not carry a T1547.001 rule annotation — the sysmon-modular configuration does not include the `BootVerificationProgram` path in its tagged registry monitoring rules. The write is captured, but without ATT&CK technique labeling.

EID 7 (ImageLoad) accounts for 10 events covering PowerShell .NET runtime DLL loads. EID 10 (ProcessAccess) and EID 17 (PipeCreate) are standard test framework artifacts.

**Security (31 events — EIDs 4688, 4798, 4799):**

This dataset contains an unusually large number of Security events (31 vs. 12 in the defended variant) driven primarily by EID 4799 (19 events) and EID 4798 (5 events).

EID 4798 (`A user's local group membership was enumerated`) fires five times — once each for `Administrator`, `Guest`, `mm11711`, `DefaultAccount`, and `WDAGUtilityAccount` on `ACME-WS06`, with `SubjectUserSid: S-1-5-18` performing the enumeration. This is triggered by WMI provider initialization (`WmiPrvSE.exe`) enumerating local group memberships as part of WMI startup.

EID 4799 (`A security-enabled local group membership was enumerated`) fires 19 times — the WMI provider performing security group enumeration across `Administrators`, `Remote Desktop Users`, `Remote Management Users`, `Users`, and `Distributed COM Users`. This is standard WMI provider host initialization behavior.

EID 4688 captures all process creations:
- `WmiPrvSE.exe`
- `cmd.exe` with the full `reg add BootVerificationProgram` command
- `reg.exe` with the add arguments
- `cmd.exe` with the `reg delete BootVerificationProgram` cleanup
- `reg.exe` with the delete arguments

All processes ran as `NT AUTHORITY\SYSTEM` or `ACME-WS06$`.

**PowerShell (96 events — EIDs 4103, 4104):**

EID 4104 script blocks are PowerShell runtime boilerplate. The test action executes via `cmd.exe /c reg add`, generating no substantive PowerShell script blocks. The cleanup stub is the largest EID 4104 event.

## What This Dataset Does Not Contain

- No boot-time execution of `iexplore.exe` occurs. The system was not rebooted after the persistence entry was created.
- The Sysmon EID 13 for this path lacks a T1547.001 rule annotation — detection via Sysmon requires a registry path filter on `BootVerificationProgram`, which is absent from the sysmon-modular baseline configuration.
- The WMI provider activity (EID 4798, 4799) is coincidental background noise from OS initialization during the test window, not related to the persistence technique.

## Assessment

This dataset demonstrates a persistence technique with a very specific registry path (`HKLM\System\CurrentControlSet\Control\BootVerificationProgram`) that is essentially unoccupied on any legitimate Windows installation. The registry write is captured in Sysmon EID 13 (without technique annotation) and in Security EID 4688 via `reg.exe` command line arguments.

The undefended run produces significantly more Security events than the defended variant (31 vs. 12) due to WMI provider initialization activity coinciding with the test window. This is an example of background OS noise that is independent of Defender state — the WMI enumeration would occur in either condition. The persistence action itself generates the same core telemetry in both variants.

## Detection Opportunities Present in This Data

The following observable events in this dataset support detection:

- **Sysmon EID 13** with `TargetObject` containing `BootVerificationProgram\ImagePath` — any write to this path is suspicious. This event is present in the dataset without a T1547.001 rule tag, meaning a detection must use the path string directly rather than relying on the sysmon-modular rule annotation.

- **Security EID 4688** recording `reg.exe` or `cmd.exe` with arguments referencing `BootVerificationProgram` — the key name itself is a high-confidence indicator when seen in any command line audit.

- **Process chain**: `powershell.exe` → `cmd.exe` → `reg.exe add HKLM\System\CurrentControlSet\Control\BootVerificationProgram` as `NT AUTHORITY\SYSTEM` — this combination has no legitimate operational context.

- **The presence of any `ImagePath` value under `BootVerificationProgram`** in a registry scan or hunt is a definitive indicator. In this dataset the value `C:\Program Files\Internet Explorer\iexplore.exe` is visible in both EID 13 and EID 4688.

- **EID 4798 context**: while the local group membership enumeration events are unrelated to this test, their presence alongside other indicators helps correlate the timing of WMI provider activity with the test execution window for timeline reconstruction.
