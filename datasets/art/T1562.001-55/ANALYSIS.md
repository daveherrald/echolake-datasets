# T1562.001-55: Disable or Modify Tools — Disable EventLog-Application Auto Logger Session Via Registry - PowerShell

## Technique Context

MITRE ATT&CK T1562.001 covers disabling or modifying security tools and logging infrastructure. This test performs the same Auto Logger disablement as T1562.001-54 — setting `HKLM\System\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\Start` to `0` — but uses PowerShell's `New-ItemProperty` cmdlet instead of `reg.exe`. As with T1562.001-49 (PowerShell vs reg.exe for Defender policy), the PowerShell approach eliminates child process creation, making the technique visible primarily through PowerShell logging rather than process creation events. This illustrates how the same registry write can present very different telemetry profiles depending on the execution method.

## What This Dataset Contains

**PowerShell (4104 / 4103):** The technique payload is fully captured:

Script block (4104):
```powershell
New-ItemProperty -Path HKLM:\System\CurrentControlSet\Control\WMI\Autologger\EventLog-Application -Name Start -Value 0 -PropertyType "DWord" -Force
```
Module logging (4103) records the `New-ItemProperty` cmdlet invocation with full parameter bindings:
- `Path = "HKLM:\System\CurrentControlSet\Control\WMI\Autologger\EventLog-Application"`
- `Name = "Start"`
- `Value = "0"`
- `PropertyType = "DWord"`
- `Force = "True"`

**Sysmon Event 1:** Process creation for `whoami.exe` (test framework pre-check) and the test framework PowerShell with the technique script block as a command argument. The full `New-ItemProperty` command is visible in the Sysmon 1 command line for the test framework PowerShell.

**Security (4688):** Process creation/termination for the outer test framework PowerShell, `whoami.exe`, and `conhost.exe`. No `cmd.exe` or `reg.exe` child processes — the technique runs entirely within PowerShell.

**Sysmon Events 7, 10, 17:** DLL loads, cross-process access, and pipe creation events from the test framework PowerShell initialization — standard noise common to all tests in this series.

## What This Dataset Does Not Contain (and Why)

**No Sysmon 13 (RegistryValue Set):** As with T1562.001-54, the Sysmon registry monitoring configuration does not capture writes to the `WMI\Autologger\EventLog-Application` path. The write is confirmed only through the PowerShell cmdlet logging.

**No Sysmon ProcessCreate for `reg.exe` or `cmd.exe`:** Because `New-ItemProperty` runs in-process, no additional process creation events are generated. This is the same contrast as T1562.001-48 vs T1562.001-49.

**No immediate Event Log disruption:** The Auto Logger change is boot-time; no immediate disruption events are present.

**No write confirmation beyond PowerShell:** Unlike `reg.exe` which has a visible exit code in the Security 4689 event, the in-process PowerShell write has no separate termination event. The 4103 cmdlet invocation is the primary confirmation.

## Assessment

The technique executed successfully. The PowerShell 4103 module logging provides the most specific evidence, capturing the exact path, value name, and data. The 4104 script block captures the full command text. The primary contrast with T1562.001-54 is the absence of `reg.exe` process creation — a detection that relies solely on `reg.exe` would miss this variant entirely. The Sysmon 1 event showing the test framework PowerShell command line also exposes the technique, though this depends on the include-mode filter matching.

## Detection Opportunities Present in This Data

- **PowerShell 4104:** Script block text containing `WMI\Autologger\EventLog-Application` with `Start` and `Value 0` — specific EventLog AutoLogger disable indicator
- **PowerShell 4103:** `New-ItemProperty` with `Path` matching `EventLog-Application` and `Name = "Start"` and `Value = "0"` — parameter-level detection
- **Sysmon 1:** Test framework PowerShell process creation with `EventLog-Application` and `New-ItemProperty` visible in the command line argument
- **Coverage gap awareness:** Absence of `reg.exe` process creation for an AutoLogger disable should prompt detection engineers to ensure PowerShell-based variants are covered alongside cmd-based ones
- **Registry state hunt:** Query for `HKLM\System\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\Start = 0` regardless of how it was set — covers both T1562.001-54 and T1562.001-55
