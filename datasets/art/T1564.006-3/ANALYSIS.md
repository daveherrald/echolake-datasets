# T1564.006-3: Run Virtual Instance — Create and start Hyper-V virtual machine

## Technique Context

T1564.006 (Run Virtual Instance) is a defense-evasion technique in which an adversary runs
malicious code inside a virtual machine to avoid detection by host-based security tools.
The specific action here — creating and starting a Hyper-V VM — is the first step in that
workflow. In real attacks, threat actors have used nested virtualization to execute ransomware
or hide C2 activity from EDR products that lack visibility into the guest. This test exercises
the PowerShell Hyper-V module (`New-VM`, `Set-VMFirmware`, `Start-VM`), which is a legitimate
Windows Server/Pro feature but unusual on a domain workstation.

## What This Dataset Contains

The dataset captures 5 seconds of telemetry (14:28:05–14:28:10 UTC) from ACME-WS02, a Windows
11 Enterprise domain workstation in the acme.local domain.

**PowerShell script block logging (4104)** records the exact test payload:

```
{$VM = "Atomic VM"
New-VM -Name $VM -Generation 2
Set-VMFirmware $VM -EnableSecureBoot Off
Start-VM $VM}
```

This appears in two 4104 events — once as the outer test framework invocation (`& {...}`) and once as
the inner script block — which is normal when ART wraps test code in an anonymous call operator.

**Module logging (4103)** records `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
-Force`, the standard ART test framework setup that precedes every test execution.

**Sysmon Event 1 (Process Create)** captures `whoami.exe` launched by PowerShell, tagged by
the sysmon-modular ruleset as `technique_id=T1033,technique_name=System Owner/User Discovery`.
This is the ART pre-flight check that runs before each test.

**Sysmon Event 7 (Image Load)** captures PowerShell loading `urlmon.dll` (tagged T1574.002
DLL Side-Loading) and multiple reflective DLL injection-associated DLLs (tagged T1055). These
are characteristic of PowerShell's normal .NET runtime loading pattern.

**Sysmon Event 10 (Process Access)** captures PowerShell opening `whoami.exe` with
`GrantedAccess: 0x1FFFFF` — full access — tagged as T1055.001 DLL Injection. This is the
ART test framework waiting for the child process to exit.

**Sysmon Event 11 (File Created)** captures PowerShell writing to
`C:\Windows\System32\config\systemprofile\...\StartupProfileData-Interactive`, which is the
PowerShell profile cache written at each interactive session start.

**Sysmon Event 17 (Pipe Created)** captures the `\PSHost.*` named pipe created by each new
PowerShell instance.

**Security 4688/4689** record process creation and termination for `powershell.exe`,
`whoami.exe`, and `conhost.exe`, all under `NT AUTHORITY\SYSTEM` in logon session `0x3E7`.

**Security 4703** records token right adjustments on the SYSTEM account, a routine event
generated when PowerShell enables privileges.

## What This Dataset Does Not Contain (and Why)

**No Hyper-V service or driver events.** The test creates and starts a VM using
`New-VM`/`Start-VM` PowerShell cmdlets. No System log events from the Hyper-V VMM service,
Hyper-V Worker process, or associated hypervisor driver activity are present. The System event
log channel was not collected in this dataset. Whether the VM actually started and what
hypervisor-level activity occurred is not visible here.

**No Sysmon ProcessCreate for New-VM or the Hyper-V worker.** The sysmon-modular configuration
uses include-mode rules for ProcessCreate. The Hyper-V worker process (`vmwp.exe`) and related
hypervisor management processes do not match the include ruleset, so they do not appear in
sysmon.jsonl. Security 4688 would cover them if they spawned, but the Security log was filtered
to the 5-second window, and any Hyper-V worker processes may have started outside that window
or not at all if the Hyper-V role was not installed.

**No evidence of a VM actually running.** This test is most meaningful when the Hyper-V role
is installed and enabled. On a base Windows 11 workstation without the role enabled, `New-VM`
would fail silently or throw a non-terminating error. The dataset does not include any error
event indicating failure, nor any success confirmation. The real-world impact of the test on
this host cannot be determined from this telemetry alone.

**No network or DNS activity.** Unlike other ART tests that download payloads, this test is
self-contained.

## Assessment

The strongest signal in this dataset is the PowerShell script block log (4104) containing
`New-VM`, `Set-VMFirmware -EnableSecureBoot Off`, and `Start-VM`. These cmdlets on a
workstation have essentially no legitimate use. The deliberate disabling of Secure Boot is
particularly notable as an evasion-oriented configuration choice.

The majority of the 93 total events (53 PowerShell, 28 Sysmon, 12 Security) are test framework
boilerplate: `Set-ExecutionPolicy Bypass`, `Set-StrictMode` error-handling fragments, `whoami`
pre-flight, and standard DLL load activity from PowerShell startup. The technique-specific
content occupies two 4104 events.

## Detection Opportunities Present in This Data

- **PowerShell 4104**: Presence of `New-VM`, `Set-VMFirmware`, or `Start-VM` in script block
  content on a non-Hyper-V host role (workstation or member server) is a high-fidelity signal.
  Combine with the `-EnableSecureBoot Off` parameter for even higher confidence.

- **Security 4688**: `powershell.exe` spawning with a command line referencing Hyper-V cmdlets.
  The full command line is visible because command-line auditing is enabled.

- **Sysmon Event 1**: `whoami.exe` launched from `powershell.exe` running as `NT
  AUTHORITY\SYSTEM` from `C:\Windows\TEMP\` is anomalous and present before every ART test
  in this environment.

- **Sysmon Event 7**: Loading `urlmon.dll` into `powershell.exe` can indicate network-bound
  activity is forthcoming, though it also occurs during normal PS startup.
