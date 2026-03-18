# T1039-2: Data from Network Shared Drive — Copy a sensitive File over Administrative share with Powershell

## Technique Context

T1039 (Data from Network Shared Drive) covers adversaries accessing and collecting data from network-accessible file shares. This test specifically targets administrative shares — the hidden shares (`C$`, `ADMIN$`, etc.) that Windows creates automatically and that are accessible only to administrators. Using PowerShell's `Copy-Item` to retrieve a file via `\\127.0.0.1\C$\Windows\temp\Easter_Bunny.password` to a local path demonstrates the pattern of using administrative share access for data collection.

In real environments, administrative share access is a primary mechanism for lateral movement and data collection. After gaining administrative credentials, attackers enumerate or access `\\<target>\C$\` to retrieve sensitive files — configuration files, credential stores, database dumps, or documentation — without needing to establish an interactive session. The loopback address (`127.0.0.1`) is used here for the atomic test, but in practice the target would be a remote host.

Detection relies on network logon events showing administrative share access (Security EID 4624 with logon type 3, or SMB-level monitoring), object access events if auditing is configured on the target paths, and PowerShell logging capturing the `Copy-Item` command with UNC path arguments. The use of `Copy-Item` with a `\\host\C$\` path is an unusual pattern for normal user activity and a reliable behavioral indicator.

## What This Dataset Contains

This dataset contains 136 events: 104 PowerShell events, 8 Security events, and 24 Sysmon events.

The Security channel (EID 4688) captures the core attack. The primary process creation records PowerShell spawning a child PowerShell with: `copy-item -Path "\\127.0.0.1\C$\Windows\temp\Easter_Bunny.password" -Destination "$Env:TEMP\Easter_egg.password"`. This command line explicitly shows the administrative share path, the filename (`Easter_Bunny.password`), and the local destination. A cleanup EID 4688 shows the corresponding `Remove-Item` commands removing both the source and destination files.

Two EID 4985 events (transaction state change) and two EID 4663 (object access) events round out the Security channel. The EID 4663 events access `C:\Windows\servicing\Sessions` and a sessions XML file — these are background Windows servicing activity, not technique-related, but they demonstrate that object access auditing is capturing filesystem operations during the test window.

Sysmon EID 1 records the PowerShell invocation with the full `Copy-Item` command including the UNC path, tagged `technique_id=T1059.001`. EID 10 (process access) shows `powershell.exe` accessing `whoami.exe` and itself. EID 11 (file create) captures `powershell.exe` creating `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-NonInteractive` — a PowerShell profile initialization artifact from the SYSTEM context. EID 7 image loads show the standard .NET and Defender DLL chain plus `urlmon.dll`. EID 17 (pipe create) events bookend the PowerShell sessions.

Compared to the defended dataset (43 Sysmon, 10 Security, 46 PowerShell), the undefended version has slightly fewer events across all channels. In the defended case, Defender's scanning of the file copy operation generates additional Sysmon and Security events. Here the copy completes without interference, producing a leaner but complete telemetry set.

Notably, this dataset does not show a network logon (Security EID 4624 Type 3) for the `\\127.0.0.1\C$` access — the loopback administrative share access happens over the local network stack and may authenticate via existing cached credentials or the SYSTEM context's implicit administrative access to the local machine, bypassing a new logon event.

## What This Dataset Does Not Contain

No Security EID 4624 (logon) or EID 4776 (credential validation) events appear for the administrative share access, which is expected when the accessing account already has an established session or when SYSTEM accesses a local admin share. In a realistic remote-target scenario, you would expect network logon events on the target host.

No DNS queries or network connection events appear for the loopback address. The file copy itself — the actual bytes transferred over the administrative share — is not visible in event log telemetry. No file creation event (Sysmon EID 11) captures the creation of `Easter_egg.password` in `$env:TEMP`.

The `Easter_Bunny.password` source file creation on the local C$ share is not visible — it was presumably a pre-existing artifact or created outside the capture window.

## Assessment

This is a focused, clean dataset for administrative share data collection. The Security EID 4688 command line with the explicit `\\127.0.0.1\C$\` UNC path is the primary detection signal. The dataset correctly represents what PowerShell-based administrative share access looks like at the process level. For remote-host scenarios, this pattern would be accompanied by network logon events on the target — this dataset is most useful as the "initiating host" component of a two-host detection scenario.

The undefended version confirms that Defender does not block `Copy-Item` over administrative shares — this technique operates entirely within legitimate Windows functionality.

## Detection Opportunities Present in This Data

1. EID 4688 or Sysmon EID 1 for `powershell.exe` with a command line containing `Copy-Item` and a UNC path beginning with `\\<host>\C$\` or `\\<host>\ADMIN$\` is the primary detection signal for PowerShell-based administrative share data collection.

2. Any process creation event for `powershell.exe` with arguments containing `C$`, `ADMIN$`, or other default administrative share names combined with file copy verbs (`Copy-Item`, `Robocopy`, `xcopy`) should be flagged.

3. EID 4663 (object access) events on sensitive target files combined with a temporal correlation to remote PowerShell process creation events (where the accessing process is `powershell.exe` or `System` from a remote session) can surface the collection activity.

4. Sysmon EID 11 for a file creation event where a file with a sensitive-looking name extension (`.password`, `.key`, `.credential`, `.pfx`, `.pem`) is written to a local directory by `powershell.exe` in a SYSTEM context indicates collection of sensitive material.

5. The pattern of `Copy-Item` from a `\\127.0.0.1\C$\` or `\\localhost\C$\` path is particularly suspicious because it indicates the attacker is testing local admin share access, often as a prerequisite to attempting the same against remote hosts using collected credentials.
