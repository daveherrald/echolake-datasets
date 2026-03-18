# T1007-7: System Service Discovery — System Service Discovery via Services Registry Enumeration

## Technique Context

T1007 System Service Discovery describes an attacker's enumeration of running and installed services to understand the target environment. Knowing what services are running informs decisions about lateral movement (which services might be exploitable), privilege escalation (which service accounts have elevated privileges), persistence candidates (which services could be hijacked or replaced), and defensive posture (which security tools are running as services).

This test variant reads service configuration directly from the Windows registry rather than using the Service Control Manager API. The PowerShell script queries `HKLM:\SYSTEM\CurrentControlSet\Services` using the PS registry provider (`Get-ChildItem`), then reads `DisplayName`, `ImagePath`, and `Start` values for each service key. This bypasses the SCM and the access controls it enforces, and is harder to correlate with service-specific audit events since no SCM API is called.

The technique generates a significant volume of PowerShell logging because `Get-ItemProperty` is called once per service key — a modern Windows system has hundreds of services, so the resulting EID 4103 event stream is distinctive in its volume and regularity. Detection focuses on the PowerShell command line targeting `HKLM:\SYSTEM\CurrentControlSet\Services`, the high volume of registry read invocations, and the process chain (PowerShell → registry provider access pattern).

Defender does not block this technique in either the defended or undefended variant, as registry reads via PowerShell's built-in provider are indistinguishable from administrative scripting.

## What This Dataset Contains

The PowerShell channel contains 780 events — 698 EID 4103 (CommandInvocation) and 82 EID 4104 (ScriptBlock). This is the largest PowerShell event volume in this batch and reflects each `Get-ItemProperty` call for every service registry key generating its own EID 4103 record. In the defended version, there were 739 PowerShell events, making the undefended run essentially identical in PowerShell volume — confirming Defender's absence doesn't change this technique's execution profile.

The Security channel shows the key EID 4688 capturing the complete PowerShell command line:

```
"powershell.exe" & {Get-ChildItem -Path 'HKLM:\SYSTEM\CurrentControlSet\Services' | ForEach-Object { $p = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue [PSCustomObject]@{ Name = $_.PSChildName DisplayName = $p.DisplayName ImagePath = $p.ImagePath StartType = $p.Start } }}
```

This is the technique's entry point — PowerShell spawned as SYSTEM (subject `ACME-WS06$`, logon `0x3e7`) enumerating all services and constructing a structured output with name, display name, image path, and start type.

The Security channel also contains 7 EID 5379 (Credential Manager read) events against the `ACME-WS06$` machine account, which appear to be a background operation by the credential subsystem running concurrently.

Sysmon EID 29 (File Executable Detected) events appear in the samples, showing Defender's signature updater (`mpam-5817d33a.exe`) detecting newly created executable files in the Network Service temp directory — specifically files named like `F748A3E2-03...`. These are the Defender VDM update files, not attack artifacts.

The timestamp range (22:48:01 to 22:48:09) shows the service enumeration completed in approximately 8 seconds — fast enough to suggest in-memory processing rather than writing the full service list to disk, though the complete PowerShell EID 4103 stream in the full dataset would contain each service's data.

## What This Dataset Does Not Contain

There are no Sysmon EID 12/13 registry access or modification events — the PS registry provider reads through a different code path that doesn't always trigger Sysmon's registry monitoring rules, which are typically configured for registry writes rather than bulk reads.

The Security EID 4688 samples capture only the initial PowerShell process creation and the whoami check. The individual `Get-ItemProperty` calls are not reflected in EID 4688 since they're in-process operations rather than new process creations. The cleanup or data exfiltration step (if any) is not captured in the available samples.

The actual service enumeration output — the list of service names, image paths, and start types — is not preserved in event logs. It would have been printed to PowerShell's output stream and not captured in any event.

## Assessment

The primary value of this dataset is the high-volume, distinctive PowerShell EID 4103 pattern that characterizes mass registry enumeration. The 698 CommandInvocation events combined with the EID 4688 command line evidence provide a complete picture for detection engineering: you can model both the initial command (EID 4688) and the behavioral footprint of systematic enumeration (the 4103 cascade). The fact that Defender doesn't interfere with this technique in either variant means both the defended and undefended datasets are suitable as baselines for service discovery detection rules.

## Detection Opportunities Present in This Data

1. Security EID 4688 with a PowerShell command line containing `Get-ChildItem -Path 'HKLM:\SYSTEM\CurrentControlSet\Services'` is a specific and moderately rare command that legitimate administrators use infrequently and not typically against all services at once.

2. A burst of PowerShell EID 4103 CommandInvocation events all showing `Get-ItemProperty` calls in rapid succession (within seconds) against `HKLM:\SYSTEM\CurrentControlSet\Services\*` paths is a volume-based behavioral indicator worth alerting on as a threshold.

3. The combination of a `Get-ChildItem` on the Services registry key followed by a `ForEach-Object` pipeline with `Get-ItemProperty` and `PSCustomObject` construction in a single PowerShell session is the specific script pattern used here — EID 4104 ScriptBlock events in the full dataset will contain this structure.

4. PowerShell EID 4103 events showing `Get-ItemProperty` calls where the `Path` property systematically iterates through well-known service key names (`.NET CLR Data`, `1394ohci`, `AarSvc`, in alphabetical order) indicates automated enumeration rather than manual administrative work.

5. Sysmon EID 1 showing `powershell.exe` spawned as NT AUTHORITY\SYSTEM with a command line referencing `CurrentControlSet\Services` and `ForEach-Object` or `Get-ChildItem` is immediately suspicious in an environment where administrative tools would typically use the SCM API or `sc query`.
