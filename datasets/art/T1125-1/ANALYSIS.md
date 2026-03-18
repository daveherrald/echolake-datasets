# T1125-1: Video Capture — Registry artefact when application use webcam

## Technique Context

MITRE T1125 Video Capture involves adversaries capturing video recordings from connected cameras to collect intelligence on user activity, gather reconnaissance for social engineering, or document sensitive information. This technique is particularly concerning in corporate environments where webcams may capture confidential meetings, documents, or conversations.

Windows maintains detailed privacy consent logs for camera access in the CapabilityAccessManager registry structure. When applications access the webcam, Windows records LastUsedTimeStart and LastUsedTimeStop timestamps as forensic artifacts. The detection community focuses on monitoring these registry locations, unusual camera access patterns, and processes that shouldn't typically interact with video devices.

## What This Dataset Contains

This dataset demonstrates registry-based simulation of webcam usage artifacts rather than actual video capture. The core activity occurs through PowerShell spawning cmd.exe to execute two reg.exe commands that manually create webcam consent store entries:

```
"cmd.exe" /c reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\NonPackaged\C:#Windows#Temp#atomic.exe /v LastUsedTimeStart /t REG_BINARY /d a273b6f07104d601 /f & reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\NonPackaged\C:#Windows#Temp#atomic.exe /v LastUsedTimeStop /t REG_BINARY /d 96ef514b7204d601 /f
```

Sysmon EID 13 events capture both registry value creations with the TargetObject paths clearly showing webcam consent store manipulation. The process chain is: PowerShell (PID 39804) → cmd.exe (PID 17420) → reg.exe (PID 10140) and reg.exe (PID 2752). Security channel EID 4688 events provide complete command-line visibility for all spawned processes.

## What This Dataset Does Not Contain

This dataset lacks actual webcam interaction telemetry. There are no API calls to camera hardware, no DirectShow or Media Foundation events, and no actual video capture processes. The test simulates webcam usage artifacts by directly writing registry entries rather than triggering them through legitimate camera access.

Additionally, there are no Sysmon ProcessCreate events for the PowerShell processes themselves due to the sysmon-modular include-mode filtering, though Security 4688 events provide process creation visibility. The PowerShell script block logs contain only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy) rather than the actual registry manipulation commands.

## Assessment

This dataset provides excellent coverage for detecting registry-based webcam consent artifacts but limited value for detecting actual video capture behavior. The Sysmon EID 13 registry monitoring combined with process creation chains offers strong detection opportunities for this specific forensic artifact. However, defenders should supplement this with additional monitoring for legitimate camera access APIs and unusual process behavior around video devices.

The registry manipulation approach is useful for understanding post-incident forensics but doesn't represent how most malware would actually capture video. Real video capture typically involves DirectShow, Media Foundation, or direct device APIs that would generate different telemetry patterns.

## Detection Opportunities Present in This Data

1. Monitor Sysmon EID 13 registry writes to `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\*` paths for webcam access artifacts

2. Detect reg.exe processes with command lines containing "CapabilityAccessManager\ConsentStore\webcam" paths as potential privacy consent manipulation

3. Alert on manual creation of LastUsedTimeStart and LastUsedTimeStop registry values in webcam consent store locations

4. Monitor PowerShell spawning cmd.exe chains that execute registry manipulation commands against privacy consent stores

5. Correlate registry writes to webcam consent paths with processes that don't typically require camera access (especially system utilities like reg.exe)

6. Track unusual patterns in webcam consent timestamp values that don't correspond to legitimate application camera usage

7. Flag registry manipulation of NonPackaged application camera consent for applications in temporary directories or suspicious file paths
