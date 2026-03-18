# T1518.001-9: Security Software Discovery — Security Software Discovery - Windows Defender Enumeration

## Technique Context

T1518.001 (Security Software Discovery) covers adversary attempts to identify what security
products are installed and configured on a compromised host. This test enumerates Windows
Defender specifically, querying service state, current protection status, and active threat
detections using built-in PowerShell cmdlets. This reconnaissance step is common early in an
intrusion to understand what defenses are present before proceeding with evasion or payload
execution.

## What This Dataset Contains

The test runs three PowerShell cmdlets in a single inline command block, executed as
NT AUTHORITY\SYSTEM:

```
powershell.exe & {Get-Service WinDefend
Get-MpComputerStatus
Get-MpThreat}
```

**Sysmon (46 events, EIDs 1, 7, 10, 11, 17):**
The Sysmon ProcessCreate (EID 1) for this command is captured with RuleName
`technique_id=T1083,technique_name=File and Directory Discovery`, reflecting the
sysmon-modular config's classification. The full command line is preserved verbatim. A
preceding `whoami.exe` invocation (RuleName `technique_id=T1033`) is also captured — this is
the ART test framework pre-flight check, not part of the technique itself. The bulk of the 46 events
are EID 7 (ImageLoad) entries for the two PowerShell processes that start up, recording DLL
loads with RuleNames including `T1055/Process Injection`, `T1059.001/PowerShell`, and
`T1574.002/DLL Side-Loading`. Two EID 17 named pipe creation events (`\PSHost.*`) record
PowerShell host startup. EID 11 records PowerShell's touch of
`C:\Windows\System32\config\systemprofile\AppData\Local\...\StartupProfileData-Interactive`.
EID 10 (ProcessAccess) events fire from the test framework PowerShell process opening the child
process, tagged `technique_id=T1055.001`.

**Security (10 events, EIDs 4688, 4689, 4703):**
4688 records creation of `whoami.exe` and a child `powershell.exe` running the enumeration,
with full command-line logging enabled. 4689 records their exits with status 0x0. A 4703
(token right adjusted) event records the SYSTEM logon session's privilege adjustment.

**PowerShell (40 events, EIDs 4103, 4104):**
Two 4103 (module logging) events record `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass` — the ART test framework's standard execution policy bypass, present at the
start of every test. The remaining events are 4104 (script block logging) entries for
PowerShell's internal formatter stubs (`Set-StrictMode -Version 1; $_.PSMessageDetails`,
`$_.ErrorCategory_Message`, etc.). The actual `Get-Service`/`Get-MpComputerStatus`/`Get-MpThreat` invocations are captured in the command line visible in EID 4688 and Sysmon EID 1,
but the cmdlet output itself is not logged — script block logging captures the code, not
return values.

## What This Dataset Does Not Contain (and Why)

**Cmdlet output / enumeration results:** PowerShell script block logging records script text,
not output. The values returned by `Get-MpComputerStatus` (e.g., `RealTimeProtectionEnabled`,
`AntivirusEnabled`) and `Get-MpThreat` (threat names, detection history) do not appear in any
event. A defender cannot determine from this telemetry what Defender told the adversary.

**Sysmon ProcessCreate for the discovery cmdlets directly:** The discovery commands run inside
the parent `powershell.exe` process rather than spawning new processes, so there is no
additional EID 1 for `Get-MpComputerStatus`. The Sysmon config's include-mode filtering would
suppress a generic `powershell.exe` ProcessCreate in any case; it fires here only because the
command line matches a file-and-directory-discovery include pattern.

**Application and WMI events:** These channels were collected but produced no events relevant
to this test execution (verified in provenance source counts for this window).

## Assessment

The test completed successfully from an adversary perspective — all three cmdlets ran as
SYSTEM with exit code 0x0 and Defender did not block native PowerShell cmdlets querying its
own status. The telemetry is rich at the process creation layer (full command line in both
4688 and Sysmon EID 1) but contains no evidence of what was discovered. Detection depends
entirely on recognizing the characteristic command pattern before any results are acted upon.

## Detection Opportunities Present in This Data

- **Sysmon EID 1 / Security 4688:** Command line contains `Get-MpComputerStatus` and
  `Get-MpThreat` — high-fidelity indicators of Defender status enumeration. Parent is
  `powershell.exe` (ART test framework) with no script path, which is unusual for legitimate
  administration.
- **Sysmon EID 1 / Security 4688:** `whoami.exe` spawned from `powershell.exe` with no
  interactive session (`TerminalSessionId: 0`) and SYSTEM integrity — consistent with
  automated execution rather than a logged-on user.
- **PowerShell EID 4103:** `Set-ExecutionPolicy Bypass -Scope Process` is a reliable
  test framework artifact; it also appears in real-world post-exploitation scripts and warrants
  review when combined with enumeration cmdlets.
- **Sysmon EID 10:** ProcessAccess from one PowerShell process into another (tagged
  `T1055.001`) is worth noting in the context of the surrounding Defender enumeration
  sequence, though it reflects legitimate PowerShell internals in this case.
