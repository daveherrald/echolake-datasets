# T1548.002-13: Bypass User Account Control — UACME Method 34

## Technique Context

UACME Method 34 exploits the Windows `WinSAT` (Windows System Assessment Tool) auto-elevation
mechanism. `WinSAT.exe` runs with `autoElevate=true` in its manifest. By abusing DLL search
order in the directory from which WinSAT loads, an attacker can cause WinSAT to load a malicious
DLL when it auto-elevates, resulting in elevation without a UAC prompt. The ART test invokes:
`cmd.exe /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\uacme\34 Akagi64.exe"`

## What This Dataset Contains

**Sysmon (28 events):** EID 7 (ImageLoad), EID 11 (FileCreated), EID 17 (PipeCreated),
EID 1 (ProcessCreate), EID 10 (ProcessAccess). Process creates (EID 1):

- `WmiPrvSE.exe` spawned by `svchost.exe` (rule: `T1047`) — WMI provider activation
- `whoami.exe` (ART pre-check, parent: PowerShell)
- `cmd.exe` with command line:
  `"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\uacme\34 Akagi64.exe"`
  (parent: PowerShell)

**Security (16 events):** EID 4688/4689, EID 4703, EID 4624 (logon), EID 4627 (group membership),
EID 4672 (special privileges). The 4624 event shows a Type 5 (service) logon for `NT AUTHORITY\SYSTEM`
with `Elevated Token: Yes` — this is the WMI provider service startup, not a UAC bypass success.
EID 4672 records the SYSTEM privilege set including SeDebugPrivilege, SeImpersonatePrivilege, and
SeDelegateSessionUserImpersonatePrivilege.

**PowerShell (34 events):** Boilerplate ART test framework scriptblocks and `Set-ExecutionPolicy -Bypass`.

## What This Dataset Does Not Contain (and Why)

**No WinSAT.exe execution** — Defender blocked Akagi64.exe before it could trigger the WinSAT
DLL hijack. No `winsat.exe` process creation or DLL load events are present.

**No elevated child process from WinSAT** — the bypass mechanism requires WinSAT to load the
malicious DLL and subsequently spawn a payload; neither event is present.

**No DLL plant artifacts** — Method 34 requires writing a DLL to a location on WinSAT's search
path. No Sysmon EID 11 events for such a write appear.

**The logon and privilege events (4624/4627/4672) are not bypass artifacts** — they represent
WMI service provider initialization within the test window, not elevation achieved by the
technique. This is an important disambiguation for analysts using this dataset.

## Assessment

This dataset shows a **blocked UACME attempt** with slightly richer ambient system activity than
other UACME tests in this series: WMI provider activation (EID 1 for `WmiPrvSE.exe`) and service
logon events (4624/4627/4672) are present due to system background activity during the test
window. These events are **not** related to the UAC bypass attempt. The technique-specific signal
remains confined to the cmd.exe invocation of `34 Akagi64.exe`.

## Detection Opportunities Present in This Data

- **Security EID 4688 / Sysmon EID 1:** `cmd.exe` with `34 Akagi64.exe` or
  `ExternalPayloads\uacme\34` in the command line
- **Behavioral:** Monitoring for `winsat.exe` launched from unusual parents, or DLL loads into
  `winsat.exe` from non-standard paths, would detect a successful Method 34 bypass
- **Security EID 4624/4627/4672 context:** Service logon events in close temporal proximity to
  suspicious process creation events should not be automatically correlated as UAC bypass success;
  verify the logon type and subject
- **Sysmon EID 1 rule tags:** `WmiPrvSE.exe` creating processes tagged `T1047` is ambient but can
  serve as environmental context when building temporal correlation windows around the attack
