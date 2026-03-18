# T1574.009-1: Path Interception by Unquoted Path — Path Interception by Unquoted Path - Execution of program.exe as service with unquoted service path

## Technique Context

T1574.009 (Hijack Execution Flow: Path Interception by Unquoted Path) exploits a Windows service configuration vulnerability. When a service's `ImagePath` registry value contains spaces and is not enclosed in quotation marks, Windows attempts to resolve the executable path by trying each prefix as a possible binary. For example, a path of `C:\Program Files\My Service\service.exe` causes Windows to try `C:\Program.exe`, then `C:\Program Files\My.exe`, before finding the real binary. An attacker who can write a binary to an earlier interpreted location wins execution when the service starts.

This test creates a service with an unquoted binary path (`C:\Program Files\windows_service.exe`), installs a test binary at that location, and starts the service.

## What This Dataset Contains

The dataset captures 77 events across Sysmon (33), Security (17), PowerShell (26), and System (1) logs collected over approximately 5 seconds on ACME-WS02.

**The full service creation and start sequence is captured:**

Sysmon Event 1 shows the attack commands:
- `cmd.exe /c copy "C:\AtomicRedTeam\atomics\T1574.009\bin\WindowsServiceExample.exe" "C:\Program Files\windows_service.exe"`
- `sc create "Example Service" binpath= "C:\Program Files\windows_service.exe" Displayname= "Example Service" ...`
- `sc start "Example Service"`

Sysmon Event 13 (Registry Value Set) shows `services.exe` writing the service registration to the registry:
- `HKLM\System\CurrentControlSet\Services\Example Service\Start` — `DWORD (0x00000002)` (auto-start)
- `HKLM\System\CurrentControlSet\Services\Example Service\ImagePath` — `C:\Program Files\windows_service.exe` (the unquoted path)
- `HKLM\System\CurrentControlSet\Services\Example Service\Type` — `DWORD (0x00000010)` (own-process service)
- `HKLM\System\CurrentControlSet\Services\Example Service\ObjectName` — `LocalSystem`
- `HKLM\System\CurrentControlSet\Services\Example Service\DisplayName` — `Example Service`

Sysmon Event 11 (File Created) captures the binary drop to `C:\Program Files\windows_service.exe`.

System Event 7045 records the new service installation: `Service Name: Example Service`, `Service File Name: C:\Program Files\windows_service.exe`.

Sysmon Event 1 shows `wmiprvse.exe -Embedding` launched by WMI, which is routine background WMI activity that occurs concurrently.

Sysmon Event 7 (Image Loaded) shows WMI utility DLLs loaded, including `wmiutils.dll` — associated with the WMI process spawned in the background.

## What This Dataset Does Not Contain (and Why)

**No execution via the unquoted path ambiguity.** The service binary was placed at the correct full path and started directly. The unquoted path vulnerability would be exploited by placing `C:\Program.exe` or `C:\Program Files\windows_service.exe`-prefixed binaries that Windows tries first. This test demonstrates service creation with an unquoted path but does not demonstrate the interception itself.

**No privilege escalation artifacts.** The test ran as `NT AUTHORITY\SYSTEM`, so no privilege change occurred. In a real attack, this technique is used by a lower-privilege user to escalate to SYSTEM when a high-privilege service starts.

**No Sysmon Event 1 for the service binary running.** The `WindowsServiceExample.exe` process is not on the Sysmon include-mode suspicious process list, so its process creation is absent from Sysmon; Security Event 4688 would cover this if the service actually executed.

**WMI Event 5858 (Error) would appear in wmi.jsonl** but is not bundled in this dataset's source channels — the WMI operational log was not a collection channel for this test. The `wmiprvse.exe` launch in Sysmon indicates background WMI activity unrelated to the attack.

## Assessment

This dataset provides clean telemetry for service creation with an unquoted binary path, with all the registry writes and the System 7045 service installation event fully captured. The dataset is valuable for training detections against service creation with unquoted paths — a well-known persistence and privilege escalation technique that is straightforward to detect via registry content inspection. The System 7045 event combined with the registry `ImagePath` value lacking quotes is a reliable, low-false-positive detection opportunity.

## Detection Opportunities Present in This Data

- **System Event 7045**: New service installed with `Service File Name: C:\Program Files\windows_service.exe` — lack of quotation marks around a path containing spaces is the defining indicator of this vulnerability.
- **Sysmon Event 13**: `HKLM\System\CurrentControlSet\Services\Example Service\ImagePath` set to an unquoted path with spaces — registry-level visibility of the vulnerable configuration.
- **Sysmon Event 1**: `sc.exe create ... binpath= "C:\Program Files\windows_service.exe"` — the sc.exe command line reveals the unquoted path at creation time.
- **Sysmon Event 11**: Binary written to `C:\Program Files\windows_service.exe` by `cmd.exe` — executable dropped to Program Files by a non-installer process.
- **Security Event 4688**: `sc.exe` and `cmd.exe` process creation with service creation arguments — correlates with the registry and file events.
- **Sysmon Event 1**: `wmiprvse.exe -Embedding` launch — concurrent background WMI activity; useful context for distinguishing attack traffic from environment noise.
