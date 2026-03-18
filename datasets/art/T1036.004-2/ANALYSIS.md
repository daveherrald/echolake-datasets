# T1036.004-2: Masquerade Task or Service — Creating W32Time similar named service using sc

## Technique Context

T1036.004 Masquerade Task or Service involves adversaries disguising malicious services or scheduled tasks by naming them similarly to legitimate Windows services to avoid detection. The W32Time service (Windows Time Service) is a prime target for masquerading due to its ubiquity and typically benign appearance to administrators. This technique aims to blend malicious persistence mechanisms into the normal service landscape, exploiting trust in familiar-looking service names.

The detection community focuses on several key indicators: services created with names similar to legitimate services but with suspicious binary paths, services pointing to unusual executables or command lines, and the creation of services in non-standard locations. The sc.exe utility is commonly used for service creation, making it a critical detection pivot point.

## What This Dataset Contains

This dataset captures a complete service masquerading attack creating a service named "win32times" (similar to the legitimate "W32Time" service). The attack chain begins with PowerShell launching a cmd.exe process via Security EID 4688: `"cmd.exe" /c sc create win32times binPath= "cmd /c start c:\T1036.004_NonExistingScript.ps1" & sc qc win32times`.

The key execution sequence shows:
1. PowerShell (PID 2916) spawning cmd.exe (PID 1672)
2. cmd.exe executing sc.exe (PID 6244) with command: `sc create win32times binPath= "cmd /c start c:\T1036.004_NonExistingScript.ps1"`
3. A second sc.exe (PID 7952) querying the created service: `sc qc win32times`

The service creation generates multiple registry modifications via Sysmon EID 13 events from services.exe (PID 740):
- `HKLM\System\CurrentControlSet\Services\win32times\ImagePath` set to "cmd /c start c:\T1036.004_NonExistingScript.ps1"
- Service type set to 0x00000010 (user mode service)
- Service configured to run as LocalSystem
- Start type set to 0x00000003 (demand start)

System EID 7045 confirms service installation: "A service was installed in the system. Service Name: win32times Service File Name: cmd /c start c:\T1036.004_NonExistingScript.ps1"

## What This Dataset Does Not Contain

The dataset lacks telemetry showing the malicious service actually starting or executing its payload (c:\T1036.004_NonExistingScript.ps1). Since this is a non-existent script, any attempt to start the service would fail, but no such attempt appears in the data. The dataset also doesn't contain file system events showing creation of the referenced PowerShell script, as it doesn't exist.

The PowerShell channel contains only execution policy bypass boilerplate and error handling scriptblocks, with no evidence of the actual Atomic Red Team command that initiated the attack. Missing are any network-related events or additional persistence mechanisms that might accompany real-world service masquerading attacks.

## Assessment

This dataset provides excellent telemetry for detecting service masquerading attacks. The combination of Security 4688 process creation events with full command lines, Sysmon process creation (EIDs 1), registry modifications (EID 13), and System service installation events (EID 7045) creates multiple detection layers. The clear process lineage from PowerShell through cmd.exe to sc.exe with suspicious command-line arguments provides robust detection opportunities.

The registry events showing service configuration are particularly valuable, as they capture the malicious binary path being set. The service name similarity to legitimate Windows services (win32times vs W32Time) demonstrates the masquerading aspect clearly. The dataset effectively shows both the attack mechanics and the defensive telemetry needed for detection engineering.

## Detection Opportunities Present in This Data

1. **Suspicious sc.exe usage**: Detect sc.exe creating services with command-line interpreters (cmd, powershell) as the binary path using Security EID 4688 or Sysmon EID 1

2. **Service name masquerading**: Identify services created with names similar to legitimate Windows services but with slight variations (win32times vs W32Time) via System EID 7045

3. **Registry-based service detection**: Monitor Sysmon EID 13 events for services.exe writing ImagePath values containing suspicious command lines or interpreters to service registry keys

4. **Command-line analysis**: Flag cmd.exe processes with "/c sc create" patterns in their command lines, especially when combined with script execution commands

5. **Process ancestry chains**: Detect PowerShell spawning cmd.exe which then spawns sc.exe, particularly when the sc.exe command creates services with non-executable binary paths

6. **Service query after creation**: Identify rapid succession of service creation followed by service query operations (sc create then sc qc) on the same service name within seconds

7. **Non-standard service paths**: Alert on services configured with binary paths pointing to script files (.ps1, .bat) or command interpreters rather than executable files

8. **LocalSystem service creation**: Monitor for new services configured to run as LocalSystem with demand start type and suspicious binary paths
