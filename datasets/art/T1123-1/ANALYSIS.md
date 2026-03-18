# T1123-1: Audio Capture — using device audio capture commandlet

## Technique Context

T1123 (Audio Capture) is a Collection technique where adversaries attempt to record audio from a system's microphone to gather sensitive information from conversations, meetings, or ambient sounds. This technique is particularly valuable for espionage, corporate intelligence gathering, or capturing credentials spoken aloud. Attackers typically leverage built-in operating system capabilities, third-party tools, or custom malware to access audio devices. The detection community focuses on monitoring for unusual audio device interactions, process creation patterns involving audio recording utilities, and PowerShell cmdlets that interact with multimedia devices. This specific test demonstrates using PowerShell's audio device management capabilities, which could be leveraged by attackers who have gained initial access to a system.

## What This Dataset Contains

The dataset captures a PowerShell-based audio device enumeration and configuration attempt. The primary evidence appears in Security event 4688, showing the creation of a PowerShell process with the command line `"powershell.exe" & {$mic = Get-AudioDevice -Recording; Set-AudioDevice -ID $mic.ID; Start-Sleep -Seconds 5}`. This command attempts to enumerate recording devices using `Get-AudioDevice -Recording`, set an audio device using `Set-AudioDevice`, and then sleep for 5 seconds.

The PowerShell script block logging in event 4104 captures the actual script content: `& {$mic = Get-AudioDevice -Recording; Set-AudioDevice -ID $mic.ID; Start-Sleep -Seconds 5}`, along with the individual components `{$mic = Get-AudioDevice -Recording; Set-AudioDevice -ID $mic.ID; Start-Sleep -Seconds 5}`. Event 4103 shows the execution of `Start-Sleep` with parameter `Seconds = 5`.

Sysmon captures the process creation chain showing three PowerShell processes (PIDs 28684, 34036, 38204) with process GUID relationships, along with associated .NET runtime loading (events 7) and named pipe creation (events 17). The dataset includes normal PowerShell startup artifacts like loading of `System.Management.Automation.ni.dll`, Windows Defender integration (`MpOAV.dll`, `MpClient.dll`), and PowerShell profile creation.

## What This Dataset Does Not Contain

The dataset lacks evidence of successful audio device access or actual audio recording. The PowerShell cmdlets `Get-AudioDevice` and `Set-AudioDevice` appear to be non-standard cmdlets that are not part of the default PowerShell installation, suggesting they either failed to execute or required a third-party module that wasn't present. There are no Windows Audio Service interactions, microphone permission requests, or multimedia device access events that would indicate successful audio capture functionality.

The dataset doesn't show any file creation events that would suggest audio files being written to disk. There are no network connections that might indicate audio data exfiltration. Additionally, there's no evidence of Windows Defender blocking the technique - the processes completed with normal exit codes, suggesting the audio capture attempt simply failed due to missing dependencies rather than security controls.

## Assessment

This dataset provides moderate utility for detection engineering focused on PowerShell-based audio device interaction attempts. While the technique didn't successfully capture audio, it demonstrates the process creation patterns and PowerShell script execution that would be consistent with audio capture attempts. The Security 4688 events with command-line logging and PowerShell 4104 script block logging provide the most valuable detection data sources. The Sysmon process creation events offer additional process relationship context but don't add significant detection value beyond what Security events provide. The dataset would be stronger if it included successful audio device interaction or showed Windows Defender blocking the technique.

## Detection Opportunities Present in This Data

1. Monitor Security 4688 events for PowerShell processes with command lines containing audio-related cmdlets like "Get-AudioDevice", "Set-AudioDevice", or similar multimedia device management functions

2. Create PowerShell script block logging detections (4104) for scripts containing audio device enumeration and configuration cmdlets, particularly when combined with sleep or delay functions

3. Detect PowerShell module invocation events (4103) showing execution of multimedia-related cmdlets, especially when executed by non-interactive or system accounts

4. Monitor for unusual PowerShell process creation patterns where parent PowerShell processes spawn child PowerShell processes with audio-related parameters

5. Correlate PowerShell named pipe creation (Sysmon 17) with audio device interaction attempts to identify potential audio capture campaigns using PowerShell remoting

6. Alert on PowerShell processes loading .NET multimedia assemblies combined with audio device cmdlet execution, indicating potential audio capture tool deployment
