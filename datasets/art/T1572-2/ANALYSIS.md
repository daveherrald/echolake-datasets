# T1572-2: Protocol Tunneling — DNS over HTTPS Regular Beaconing

## Technique Context

T1572 (Protocol Tunneling) covers encapsulation of C2 traffic within other protocols.
This test extends the DoH theme by simulating structured C2 beaconing behavior: a
purpose-built script (`T1572-doh-beacon.ps1`) sends periodic DoH TXT queries to
Google's resolver at configurable intervals with jitter, mimicking how real C2 frameworks
beacon for instructions. The test runs for 30 minutes (`-RunTime 30`) with a 30-second
base interval and 20% jitter — producing a regular but slightly randomized heartbeat
pattern on HTTPS to `8.8.8.8`. Beaconing regularity analysis (identifying periodic
traffic with timing jitter) is a core C2 detection discipline; this dataset provides
concrete telemetry for developing and testing those detectors.

## What This Dataset Contains

**Sysmon EID 1** — process create for `powershell.exe` with the full beacon invocation:

> `CommandLine: "powershell.exe" & {Set-Location "C:\AtomicRedTeam\atomics"`
> `.\T1572\src\T1572-doh-beacon.ps1 -DohServer https://8.8.8.8/resolve -Domain 127.0.0.1.xip.io`
> `-Subdomain atomicredteam -QueryType TXT -C2Interval 30 -C2Jitter 20 -RunTime 30}`
> `RuleName: technique_id=T1059.001,technique_name=PowerShell`

**Sysmon EID 3** — outbound TCP connection from `powershell.exe`:

> `DestinationIp: 8.8.8.8 | DestinationPort: 443`

**Sysmon EID 7** — DLL image loads for PowerShell including `MpOAV.dll` (Defender
AMSI provider), annotated with T1055/T1059.001/T1574.002 rule names.

**Sysmon EID 10** — process access (T1055.001 rule) from one PowerShell to another,
representing the ART test framework's Invoke-AtomicTest wrapper calling the test process.

**Sysmon EID 11** — file creates at `SystemProfile\PowerShell\StartupProfileData-*`.

**Sysmon EID 13** — registry value sets (likely from the test framework process setup).

**Sysmon EID 17** — named pipe creation for PowerShell host processes.

**PowerShell EID 4104** — the test payload:

> `param([string]$DohServer = "https://8.8.8.8/resolve", [string]$Domain = "example.com",`
> `[string]$Subdomain = "atomicredteam", [int]$C2Interval = 30, [int]$C2Jitter = 20, [int]$RunTime = 30)`
> `...`
> `(Invoke-WebRequest "$($DohServer)?name=$Subdomain.$(Get-Random -Minimum 1 -Maximum 999999).$Domain&type=$QueryType"...)`
> `Start-Sleep -Seconds ($C2Interval * $Jitter)`

The complete beacon script source code is captured in a multi-line script block, making
the C2 timing parameters directly visible in the log.

**TaskScheduler EID 140** — task updated:
> `Task "\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask" updated by ACME\ACME-WS02$`

**Application EID 16384** — Software Protection Platform service restart scheduled:
> `Successfully scheduled Software Protection service for re-start at 2026-05-03T04:05:55Z`

These two events are unrelated OS background activity, demonstrating real-world noise
in production telemetry.

## What This Dataset Does Not Contain (and Why)

**No Sysmon EID 22 for the beacon queries.** As with T1572-1, DoH bypasses the Windows
DNS resolver — all queries go directly to `8.8.8.8:443` over HTTPS, generating no
OS-level DNS resolution events.

**No per-beacon network events.** The 125-second window (02:32:46Z to 02:34:51Z) for
a 30-minute test indicates this dataset captures only the startup phase; the Sysmon EID
3 records the initial connection, not each subsequent beacon interval.

**No Sysmon EID 1 from the beacon subprocess.** The PowerShell process running the
beacon loop is the same process as the one whose create event is captured; Sysmon's
include-mode ProcessCreate rule fires on the initial PowerShell launch.

## Assessment

This dataset is valuable for building detectors that correlate the command text (EID
4104 with explicit C2 timing parameters) with a durable network connection to a DNS
resolver IP on port 443. The beacon script source code captured in EID 4104 makes
the C2 interval and jitter parameters directly readable — a high-fidelity but
realistically unusual level of visibility that depends on PowerShell script block
logging being enabled. The TaskScheduler and Application background events provide
realistic noise context.

## Detection Opportunities Present in This Data

- **PowerShell EID 4104** — the beacon script body with `C2Interval`, `C2Jitter`,
  `RunTime` parameter names and `Invoke-WebRequest` to a DoH resolver is a strong
  contextual indicator even without the file path.
- **Sysmon EID 1 command line** — `Set-Location "C:\AtomicRedTeam\atomics"` followed
  by execution of a `.ps1` from the atomics directory is a direct indicator of ART
  test execution; in real-world scenarios, the path would differ but the DoH server
  and TXT query type arguments would remain.
- **Sysmon EID 3** — `powershell.exe` → `8.8.8.8:443` TCP connection, especially one
  that persists for the test duration (long-lived HTTPS session to a DNS resolver IP).
- **Beaconing analysis** — in network telemetry (not present here), a process making
  periodic HTTPS connections to `8.8.8.8` every ~30 seconds with slight timing variation
  would be detectable via beacon detection algorithms.
- **TaskScheduler/Application background events** — in a real investigation, the
  unrelated SvcRestartTask update and SPP scheduling events demonstrate that background
  OS activity must be filtered when building time-correlation detectors.
