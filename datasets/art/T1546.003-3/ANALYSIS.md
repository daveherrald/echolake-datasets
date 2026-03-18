# T1546.003-3: Windows Management Instrumentation Event Subscription — Windows MOFComp.exe Load MOF File

## Technique Context

T1546.003 (WMI Event Subscription) can be established not only through direct WMI API calls but also by compiling a Managed Object Format (MOF) file using `mofcomp.exe`. MOF files are plain-text schemas that define WMI classes and instances, including event subscriptions. Attackers use this approach to avoid making direct API calls that might be monitored, since `mofcomp.exe` is a trusted Windows binary and the subscription is defined in a file that may look like legitimate WMI administration. The MOF file can define all three subscription components (filter, consumer, binding) in one artifact. `mofcomp.exe` writes directly to the WMI repository on compilation, making this an on-disk technique unless the MOF file is cleaned up. Detection teams monitor for `mofcomp.exe` execution, particularly when invoked from unusual parent processes or with paths pointing to non-standard directories.

## What This Dataset Contains

The dataset spans 5 seconds (2026-03-13 23:38:48–23:38:53) on ACME-WS02 running as NT AUTHORITY\SYSTEM.

**Sysmon (47 events, IDs: 1, 7, 10, 11, 17, 19, 20, 21):** The core evidence is a Sysmon ID=1 (ProcessCreate) event for `mofcomp.exe`, tagged `technique_id=T1047,technique_name=Windows Management Instrumentation`:

```
Image: C:\Windows\System32\wbem\mofcomp.exe
CommandLine: "C:\windows\system32\wbem\mofcomp.exe" C:\AtomicRedTeam\atomics\T1546.003\src\T1546.003.mof
```

The parent is PowerShell, invoked as:

```
"powershell.exe" & {c:\windows\system32\wbem\mofcomp.exe "C:\AtomicRedTeam\atomics\T1546.003\src\T1546.003.mof"}
```

Following `mofcomp.exe` execution, Sysmon ID=19, 20, and 21 fire confirming the subscription was registered:
- ID=19: Filter `AtomicRedTeam_filter` with query `SELECT * FROM __InstanceCreationEvent Within 3 Where TargetInstance Isa "Win32_Process" And Targetinstance.Name = "notepad.exe"` in `root\subscription`
- ID=20: Consumer `AtomicRedTeam_consumer` with `Type: Command Line`, `Destination: "cmd.exe"`
- ID=21: Binding linking the two

This subscription triggers on `notepad.exe` creation rather than system uptime — a different trigger pattern from tests 1 and 2.

**WMI Activity (1 event, ID: 5861):** Confirms the binding with the full MOF content including the WQL query and `CommandLineEventConsumer` definition for `cmd.exe`.

**Application (1 event, ID: 10):** An Application log event records an error:

```
Event filter with query "SELECT * FROM __InstanceCreationEvent Within 3 Where TargetInstance Isa "Win32_Process" And Targetinstance.Name = "notepad.exe"" could not be reactivated in namespace "//./root/subscription" because of error 0x80041010.
```

Error `0x80041010` (WBEM_E_INVALID_CLASS) indicates the filter could not be immediately activated after the MOF was compiled, but this is a post-cleanup artifact rather than a Defender block.

**Security (13 events, IDs: 4688, 4689, 4703):** Process creation events for `mofcomp.exe` (4688) and its test framework predecessors.

**PowerShell (37 events, IDs: 4103, 4104):** Test framework boilerplate only.

## What This Dataset Does Not Contain

- **No MOF file content in the logs:** The `.mof` file at `C:\AtomicRedTeam\atomics\T1546.003\src\T1546.003.mof` is referenced by path but its content is not captured in any log channel. File read auditing is not enabled.
- **No consumer trigger execution:** The subscription fires on `notepad.exe` creation. No `notepad.exe` is launched in this test window, so there is no `wmiprvse.exe` spawning `cmd.exe` event.
- **No Sysmon ID=11 for the MOF file:** The MOF file itself is not written by any process in this window (it was pre-staged by ART); only a test framework PowerShell profile file is written.

## Assessment

This dataset is uniquely valuable for building detections around the `mofcomp.exe` delivery vector. The ID=1 event for `mofcomp.exe` with a path pointing to the ART atomics directory is a clear indicator, and the subsequent 19/20/21 events confirm successful subscription installation. The Application log 0x80041010 error adds an unexpected dimension — it can appear in cleanup scenarios and should not be mistaken for a failed attack. The dataset complements T1546.003-1 and -2 well: those tests show API-based subscription creation; this test shows the file-based (`mofcomp.exe`) path. Together they cover the two primary delivery mechanisms for WMI persistence.

## Detection Opportunities Present in This Data

1. **Sysmon ID=1:** `mofcomp.exe` execution with a non-system path argument (anything outside `C:\Windows\System32\wbem\`) is suspicious; `mofcomp.exe` run from scripts or via PowerShell with external MOF files is a high-confidence indicator.
2. **Security ID=4688:** `mofcomp.exe` process creation with command-line logging showing a MOF file path in user-writable directories (`%TEMP%`, `%APPDATA%`, `C:\AtomicRedTeam\`, etc.) is alertable.
3. **Sysmon ID=19 + 20 + 21 cluster:** WMI subscription registration events following `mofcomp.exe` execution within seconds confirm the MOF was applied — this sequence is rare in legitimate administration.
4. **WMI-Activity ID=5861:** Binding event with a `CommandLineEventConsumer` pointing to `cmd.exe` or PowerShell is independently alertable regardless of how the subscription was created.
5. **Application log ID=10 (0x80041010):** The post-cleanup reactivation failure error can serve as a retrospective indicator that a WMI subscription was installed and then removed, useful for hunting prior infections.
