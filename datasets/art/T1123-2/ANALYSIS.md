# T1123-2: Audio Capture — Registry artefact when application use microphone

## Technique Context

T1123 Audio Capture involves adversaries capturing audio recordings from a system to collect sensitive information from conversations, meetings, or other audio sources. While attackers often deploy malware that directly interfaces with microphone APIs, Windows systems also create forensic artifacts when applications access microphone resources. The CapabilityAccessManager in Windows 10/11 tracks application usage of privacy-sensitive capabilities like microphone access through registry entries that record when applications start and stop using these resources.

Detection engineers typically focus on process creation events for known audio capture tools, file creation of audio files, and registry modifications related to microphone permissions. This particular test simulates the registry artifacts left behind when an application uses the microphone, creating the forensic evidence that would remain after legitimate or malicious audio capture activity.

## What This Dataset Contains

This dataset captures the simulation of microphone usage artifacts through direct registry manipulation. The core technique execution occurs through Security event 4688 showing a cmd.exe process with the command line: `"cmd.exe" /c reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\NonPackaged\C:#Windows#Temp#atomic.exe /v LastUsedTimeStart /t REG_BINARY /d a273b6f07104d601 /f & reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\NonPackaged\C:#Windows#Temp#atomic.exe /v LastUsedTimeStop /t REG_BINARY /d 96ef514b7204d601 /f`.

The dataset contains two critical Sysmon 13 events showing the actual registry value creation:
- Registry key: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\NonPackaged\C:#Windows#Temp#atomic.exe\LastUsedTimeStart`
- Registry key: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\NonPackaged\C:#Windows#Temp#atomic.exe\LastUsedTimeStop`

The process chain shows PowerShell spawning cmd.exe, which then launches two separate reg.exe processes to create the registry entries. Sysmon events 1 capture the process creation for whoami.exe (process discovery), cmd.exe, and both reg.exe instances with their full command lines.

## What This Dataset Does Not Contain

This dataset does not contain actual audio capture activity or the creation of audio files. The test only simulates the registry artifacts that would be left behind after microphone usage, not the microphone access itself. There are no events showing actual microphone driver interaction, audio device access, or the creation of recorded audio files.

The PowerShell events contain only standard test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy) and do not show the actual test execution script. No network connections are present, so there's no evidence of audio data exfiltration. Additionally, there are no Windows Audio Session API events or multimedia device access events that would typically accompany legitimate audio capture.

## Assessment

This dataset provides excellent coverage for detecting registry-based forensic artifacts of microphone usage. The Sysmon 13 events capture the specific registry modifications that Windows makes when applications access microphone capabilities, making this valuable for post-incident analysis and forensic investigations. The Security 4688 events with command-line logging provide clear process execution context.

However, the dataset's utility is limited to detecting the simulation of these artifacts rather than actual audio capture techniques. For comprehensive audio capture detection, additional telemetry would be needed including audio driver events, file creation monitoring for audio formats, and API hooking for multimedia functions.

The registry path structure clearly identifies the application path (`C:#Windows#Temp#atomic.exe`) and the timing values, making this dataset excellent for building detections around CapabilityAccessManager modifications.

## Detection Opportunities Present in This Data

1. **Registry modification to CapabilityAccessManager microphone paths** - Sysmon 13 events with TargetObject containing `\CapabilityAccessManager\ConsentStore\microphone\` and values `LastUsedTimeStart` or `LastUsedTimeStop`

2. **Command-line execution of reg.exe targeting microphone consent store** - Security 4688 or Sysmon 1 with CommandLine containing `CapabilityAccessManager\ConsentStore\microphone` registry paths

3. **Batch command execution combining multiple registry operations** - Command lines using `&` to chain multiple `reg add` commands targeting microphone consent registry keys

4. **Process ancestry of registry manipulation from scripting engines** - PowerShell spawning cmd.exe which spawns reg.exe with microphone-related registry targets

5. **Binary registry data creation for microphone timing values** - Registry modifications with REG_BINARY data type targeting LastUsedTimeStart/LastUsedTimeStop values in microphone consent paths
