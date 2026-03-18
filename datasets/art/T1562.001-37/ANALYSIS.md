# T1562.001-37: Disable or Modify Tools — Evade Scanning Folder

## Technique Context

T1562.001 (Disable or Modify Tools) covers actions that weaken or circumvent security
software. This test attempts to add a path exclusion to Windows Defender using the WMIC
interface, writing to the `MSFT_MpPreference` WMI class. Adding a folder exclusion means
Defender will not scan files in that path, enabling an adversary to stage malware,
execute payloads, or store stolen data in the excluded directory without triggering
real-time protection. This is a direct precondition-setting technique, frequently performed
before dropping a payload. The WMI approach is an alternative to `Set-MpPreference` that may
evade detection rules focused only on PowerShell-based Defender tampering.

## What This Dataset Contains

The test invokes WMIC to call the `Add` method on `MSFT_MpPreference` to add the path
"ATOMICREDTEAM" as a Defender exclusion, as NT AUTHORITY\SYSTEM:

```
cmd.exe /c wmic.exe /Namespace:\\root\Microsoft\Windows\Defender class MSFT_MpPreference
call Add ExclusionPath="ATOMICREDTEAM"
```

**Sysmon (2 events, EID 3 only):**
Unusually, the only Sysmon events in this dataset are two EID 3 (Network Connection) events
from `MsMpEng.exe` — the Windows Defender service binary — making outbound TCP connections
to 48.211.71.197:443 immediately after the exclusion attempt. These are tagged with RuleName
`technique_id=T1036,technique_name=Masquerading` by the sysmon-modular config:

```
Image: C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26010.5-0\MsMpEng.exe
SourceIp: 192.168.4.12
DestinationIp: 48.211.71.197
DestinationPort: 443
```

This is Defender's telemetry upload — the engine phoning home to Microsoft after detecting
or processing the exclusion modification attempt. The T1036 Masquerading tag is a false
positive from the sysmon-modular rule; these are legitimate Defender telemetry connections.

No Sysmon EID 1 events are present because neither `cmd.exe` nor `wmic.exe` matched the
sysmon-modular ProcessCreate include patterns for this specific WMIC Defender namespace call.

**Security (13 events, EIDs 4688, 4689, 4703):**
4688 records the full execution chain: `whoami.exe` (test framework pre-flight), `cmd.exe` with the
full WMIC exclusion command, and `wmic.exe` with:
```
wmic.exe  /Namespace:\\root\Microsoft\Windows\Defender class MSFT_MpPreference
call Add ExclusionPath="ATOMICREDTEAM"
```
All processes exit with 0x0 (4689). The WMIC call completed without OS-level error. A 4703
token adjustment event is present.

**PowerShell (34 events, EIDs 4103, 4104):**
Two 4103 events record `Set-ExecutionPolicy Bypass -Scope Process` (ART test framework boilerplate).
Remaining 4104 events are PowerShell formatter stubs. No PS events specific to the WMIC
exclusion call are present since the operation executed via cmd.exe, not PowerShell.

## What This Dataset Does Not Contain (and Why)

**Confirmation that the exclusion was successfully added:** The WMIC exit code is 0x0, but
this reflects OS-level process success, not WMI method success. Whether Defender actually
accepted the exclusion modification is not logged in any channel captured here. WMI
provider method results are not surfaced in Windows event logs by default. The Defender
exclusion state before and after cannot be determined from this dataset.

**Sysmon ProcessCreate for cmd.exe and wmic.exe:** The sysmon-modular include-mode config
does not match the WMIC Defender namespace syntax used here. This is a coverage gap
specifically for WMIC-based Defender tampering via the WMI provider path. Security 4688
provides compensating coverage. Environments relying on Sysmon alone would completely miss
the attack command.

**Defender alert or block events:** No Windows Defender detection events appear. Running as
SYSTEM with full administrative privileges, modifying Defender configuration via its own WMI
interface is permitted — Defender does not block itself. No 0xC0000022 exit codes are present.

**Network destination hostname for MsMpEng connections:** The `DestinationHostname` field is
empty in both Sysmon EID 3 events; only the raw IP address (48.211.71.197) is captured.

## Assessment

The test demonstrates that WMIC-based Defender exclusion addition runs without OS-level
blocking when executed as SYSTEM. The Security 4688 channel is the sole process creation
source for the attack commands — Sysmon's include-mode filtering misses both `cmd.exe` and
`wmic.exe` here. The Sysmon EID 3 MsMpEng network connections are background Defender
telemetry, not attack traffic, and should not be interpreted as evidence of a C2 connection.
This dataset is a clear demonstration of why complementary logging (Sysmon + Security audit)
matters.

## Detection Opportunities Present in This Data

- **Security EID 4688:** `wmic.exe` with `/Namespace:\\root\Microsoft\Windows\Defender` and
  `ExclusionPath` in the command line is a high-fidelity indicator. This specific WMI method
  call has no legitimate administrative use case that would be invoked from a non-interactive
  SYSTEM session.
- **Security EID 4688 process chain:** `powershell.exe` (SYSTEM, session 0, no script) →
  `cmd.exe` → `wmic.exe` with Defender namespace is a distinctive three-hop chain detectable
  through parent-process correlation.
- **Keyword detection:** The string `MSFT_MpPreference` combined with `call Add
  ExclusionPath` in any process command line event is a reliable atomic indicator that can
  be deployed as a SIEM rule with very low false-positive rate.
- **Sysmon EID 3 MsMpEng telemetry:** While not attack traffic, the timing of MsMpEng
  outbound connections immediately following a Defender configuration command can serve as
  a corroborating signal in a timeline analysis.
- **Coverage gap visibility:** This dataset illustrates why dual coverage (Sysmon
  include-mode + Security 4688 unconditional) matters — Sysmon alone produces zero
  process-creation evidence for this test. Security audit policy is the load-bearing
  control here.
