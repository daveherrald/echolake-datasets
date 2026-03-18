# T1592.001-1: Hardware — Enumerate PlugNPlay Camera

## Technique Context

T1592.001 (Gather Victim Host Information: Hardware) covers adversary collection of hardware information about a target system prior to or during an intrusion. Camera and imaging device enumeration is a specific sub-objective: attackers may query for connected cameras to identify surveillance or recording capabilities, assess the value of a target workstation, or stage for screenshot/video capture operations. This test uses a WMI query against `Win32_PnPEntity` to enumerate Plug and Play devices classified as imaging or camera hardware.

## What This Dataset Contains

The dataset spans roughly 4 seconds across three log sources (26 Sysmon events, 11 Security events, 60 PowerShell events).

**PowerShell Event 4104** captures the attack payload verbatim:

```
Get-CimInstance -Query "SELECT * FROM Win32_PnPEntity WHERE (PNPClass = 'Image' OR PNPClass = 'Camera')"
```

**PowerShell Event 4103** records the command binding:
```
CommandInvocation(Get-CimInstance): "Get-CimInstance"
ParameterBinding(Get-CimInstance): name="Query"; value="SELECT * FROM Win32_PnPEntity WHERE (PNPClass = 'Image' OR PNPClass = 'Camera')"
```

The module logging events also capture the bulk loading of CIM cmdlet aliases (`gcim`, `ncim`, `rcim`, `scim`, `gcms`, `ncms`, `gcls`, `gcai`, `rcie`, `ncso`, `rcms`, `icim`) that are registered by the PowerShell CIM module at load time — these are standard module initialization artifacts, not attack content.

**Sysmon Event 1** (ProcessCreate) captures `whoami.exe` (tagged `technique_id=T1033`) spawned by the ART test framework and a second PowerShell process for cleanup. The Sysmon ProcessCreate filter matched these because `whoami.exe` is a known-suspicious LOLBin.

**Sysmon Event 10** (ProcessAccess) fires on the test framework PowerShell accessing a child PowerShell process, tagged `technique_id=T1055.001`.

**Sysmon Event 7** (ImageLoad) records .NET and Defender DLL loads into each PowerShell process, consistent with normal PowerShell startup.

**Security Event 4688** records process creation for `powershell.exe` and `whoami.exe`. Event 4703 records token privilege adjustment.

## What This Dataset Does Not Contain

WMI provider host (`WmiPrvSE.exe`) activity is not present — the `Get-CimInstance` call executes in-process in PowerShell and does not necessarily spawn a WMI provider host for local queries. WMI operational log events (Microsoft-Windows-WMI-Activity/Operational) are not collected in this dataset; that channel would provide additional corroboration. No network connection is captured because the query runs locally. The query result (whether cameras were found, and their names/IDs) is not recorded — PowerShell output is not captured by script block or module logging.

This VM runs on QEMU/KVM and has no physical camera device. The query would return an empty result set, which is realistic for a virtual machine but differs from what would be seen on a physical laptop with an integrated webcam.

The Sysmon include-mode ProcessCreate filter does not match `powershell.exe` executing a WMI query unless invoked in a way that triggers another include rule (e.g., via `whoami.exe` in the test framework). The actual `Get-CimInstance` call does not generate a Sysmon Event 1 for itself.

## Assessment

This dataset cleanly captures the enumeration attempt through PowerShell's logging subsystem. The query string `Win32_PnPEntity WHERE (PNPClass = 'Image' OR PNPClass = 'Camera')` appears verbatim in both Event 4104 and 4103, making it trivially detectable via keyword search. The dataset is representative of how this technique appears on a domain workstation with comprehensive PowerShell logging; the key gap is that command output is not recorded, so defenders cannot determine whether the enumeration succeeded.

## Detection Opportunities Present in This Data

- **PowerShell Event 4104**: Script blocks containing `Win32_PnPEntity` with `PNPClass = 'Image'` or `PNPClass = 'Camera'` are a precise indicator.
- **PowerShell Event 4103**: `Get-CimInstance` command binding with a WMI query targeting image or camera device classes.
- **PowerShell Event 4104**: The pattern of `Get-CimInstance` with a WQL `SELECT *` against hardware inventory classes (`Win32_PnPEntity`, `Win32_VideoController`, `Win32_USBController`, etc.) is broadly useful for detecting hardware discovery.
- **Security Event 4688**: PowerShell invoked as NT AUTHORITY\SYSTEM (logon ID 0x3E7) running a CIM/WMI hardware query warrants scrutiny in environments where SYSTEM-context PowerShell is not routine.
- Baseline: bulk registration of CIM cmdlet aliases (Set-Alias for `gcim`, `ncim`, etc.) in Event 4103 is normal module-load behavior and should not be treated as an indicator on its own.
