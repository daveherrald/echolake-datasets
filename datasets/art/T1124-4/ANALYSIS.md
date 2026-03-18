# T1124-4: System Time Discovery — System Time Discovery W32tm as a Delay

## Technique Context

System Time Discovery (T1124) involves adversaries gathering temporal information from target systems to understand timing, scheduling, and operational patterns. While often overlooked as a benign reconnaissance activity, time discovery serves critical functions in sophisticated attacks: coordinating multi-stage operations, avoiding detection during specific monitoring windows, establishing communication schedules with C2 infrastructure, and bypassing time-based security controls.

This specific test demonstrates using W32tm.exe (Windows Time Service) with the `/stripchart` parameter as both a time discovery mechanism and a built-in delay function. The detection community focuses heavily on W32tm abuse because it's a legitimate Windows utility that provides precise time synchronization data while offering convenient timing control through parameters like `/period` and `/samples`. Unlike simple `ping -n` delays, W32tm provides actual time data that adversaries can leverage for operational timing decisions.

## What This Dataset Contains

The dataset captures a complete PowerShell-initiated W32tm execution chain with excellent process telemetry. Security event 4688 shows the cmd.exe spawning with command line `"cmd.exe" /c W32tm /stripchart /computer:localhost /period:5 /dataonly /samples:2`, followed by the actual W32tm.exe process creation with `W32tm /stripchart /computer:localhost /period:5 /dataonly /samples:2`. 

The Sysmon data provides complementary ProcessCreate events (EID 1) for both cmd.exe and identifies the parent PowerShell process through process GUIDs. Notably, Sysmon EID 10 (ProcessAccess) events show PowerShell accessing both the cmd.exe and whoami.exe processes with full access rights (0x1FFFFF), providing additional process interaction context.

The technique generates a ~10-second delay between the initial PowerShell execution and completion, demonstrating the timing control capability. Process termination events (Security EID 4689) confirm successful completion with exit status 0x0 for both W32tm.exe and cmd.exe.

## What This Dataset Does Not Contain

The dataset lacks the actual time data output that W32tm would display to the console - this appears only in the process's stdout, not in Windows event logs. Network connection telemetry is absent because W32tm queried localhost rather than external time servers. The sysmon-modular configuration filtered out W32tm.exe ProcessCreate events since W32tm isn't included in the suspicious process patterns, making Security 4688 events the primary detection source for the actual W32tm execution.

No PowerShell script block logging captured the specific W32tm command - the PowerShell events contain only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass). File system artifacts from the timing operation aren't present, as W32tm's `/dataonly` parameter produces console output rather than file writes.

## Assessment

This dataset provides excellent detection engineering value for W32tm-based timing techniques. The Security 4688 events with full command-line logging offer reliable detection anchors, while Sysmon ProcessCreate events provide process relationship context. The combination of Security and Sysmon data sources creates robust coverage for this technique.

The presence of both the cmd.exe wrapper and direct W32tm execution allows detection logic development for both direct W32tm invocation and shell-wrapped execution patterns. Process access events add behavioral context that can distinguish legitimate administrative use from potential adversary timing operations.

## Detection Opportunities Present in This Data

1. **W32tm Stripchart Execution** - Security EID 4688 events showing W32tm.exe with `/stripchart` parameter, especially when combined with timing control parameters like `/period` and `/samples`

2. **W32tm Localhost Queries** - Command line analysis detecting W32tm `/stripchart` operations targeting localhost, which is uncommon in legitimate time synchronization scenarios

3. **PowerShell-Initiated Time Discovery** - Process chain analysis showing powershell.exe → cmd.exe → W32tm.exe execution sequences for time-related commands

4. **Short-Duration Time Operations** - Detection of W32tm operations with small `/samples` values (like 2) that suggest delay/timing rather than legitimate time synchronization monitoring

5. **Process Access Pattern** - Sysmon EID 10 events showing PowerShell accessing spawned timing processes with full access rights, indicating programmatic process control

6. **Time Utility Parameter Combinations** - Command line pattern matching for W32tm with `/dataonly` flag combined with timing parameters, indicating automated time data collection rather than interactive troubleshooting
