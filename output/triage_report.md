# Encoded PowerShell Triage Report

**Organization:** Detection Engineering Lab

**Classification:** Internal Use Only

---

## Summary

- Total Results: 2
- Highest Risk: High
- Highest Score: 7

---

## Detection Coverage Summary

### MITRE Techniques Covered

- T1059.001 - PowerShell (Execution)
- T1027 - Obfuscated Files or Information (Defense Evasion)

### Detection Rule Ideas

- Suspicious PowerShell EncodedCommand Execution (High)
- PowerShell Invoke-Expression Usage (Medium)

### Detection Templates

- Sigma: Suspicious PowerShell EncodedCommand (High)
- Microsoft Sentinel KQL: PowerShell EncodedCommand Execution (High)
- Microsoft Sentinel KQL: PowerShell Invoke-Expression Usage (Medium)

---

## Finding 1

### Metadata

- Timestamp: 2026-05-21T18:33:55
- Encoding: UTF-8
- Decode Level: 1
- Source Encoding: 
- Batch Item: 
- Source File: 

### Original Input

```text
cG93ZXJzaGVsbCUyRWV4ZSUyMC1lbmMlMjBJRVg=
```

### Decoded Output

```text
powershell%2Eexe%20-enc%20IEX
```

### Suspicious Keywords

- powershell
- -enc
- iex

### Risk Score

- Risk Level: High
- Score: 7

### Risk Reasons

- powershell may indicate suspicious command-line or PowerShell behavior.
- -enc may indicate suspicious command-line or PowerShell behavior.
- iex is commonly used in malicious or obfuscated script execution.

### MITRE ATT&CK Mapping

- T1059.001 - PowerShell (Execution)
  - Reason: PowerShell is commonly used for command and script execution.
- T1027 - Obfuscated Files or Information (Defense Evasion)
  - Reason: Encoded command usage may indicate command obfuscation.

### Detection Rule Mapping

- Suspicious PowerShell EncodedCommand Execution
  - Severity: High
  - Description: Detects PowerShell execution using encoded command indicators.
  - Log Sources: Microsoft Defender DeviceProcessEvents, Sysmon Event ID 1, Windows Security Event ID 4688
  - Reason: PowerShell execution with encoded command usage may indicate obfuscated script execution.
- PowerShell Invoke-Expression Usage
  - Severity: Medium
  - Description: Detects use of IEX or Invoke-Expression patterns.
  - Log Sources: Microsoft Defender DeviceProcessEvents, PowerShell Script Block Logs, Sysmon Event ID 1
  - Reason: IEX is commonly used to execute PowerShell content in memory.

### Detection Templates

- Suspicious PowerShell EncodedCommand
  - Type: Sigma
  - Severity: High
  - Description: Detects PowerShell execution using encoded command arguments.
  - Query:

```text
title: Suspicious PowerShell EncodedCommand
id: 00000000-0000-0000-0000-000000000024
status: experimental
description: Detects PowerShell execution using encoded command arguments.
author: Encoded Command Analyzer
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
    CommandLine|contains:
      - '-enc'
      - '-encodedcommand'
  condition: selection
falsepositives:
  - Administrative scripts
  - Software deployment tools
level: high
tags:
  - attack.execution
  - attack.t1059.001
  - attack.defense_evasion
  - attack.t1027
```

- PowerShell EncodedCommand Execution
  - Type: Microsoft Sentinel KQL
  - Severity: High
  - Description: Detects PowerShell process executions containing encoded command arguments.
  - Query:

```text
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("-enc", "-encodedcommand")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

- PowerShell Invoke-Expression Usage
  - Type: Microsoft Sentinel KQL
  - Severity: Medium
  - Description: Detects PowerShell command lines containing IEX or Invoke-Expression.
  - Query:

```text
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("iex", "invoke-expression")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```


---

## Finding 2

### Metadata

- Timestamp: 2026-05-21T18:33:55
- Encoding: URL
- Decode Level: 2
- Source Encoding: UTF-8
- Batch Item: 
- Source File: 

### Original Input

```text
cG93ZXJzaGVsbCUyRWV4ZSUyMC1lbmMlMjBJRVg=
```

### Decoded Output

```text
powershell.exe -enc IEX
```

### Suspicious Keywords

- powershell
- -enc
- iex

### Risk Score

- Risk Level: High
- Score: 7

### Risk Reasons

- powershell may indicate suspicious command-line or PowerShell behavior.
- -enc may indicate suspicious command-line or PowerShell behavior.
- iex is commonly used in malicious or obfuscated script execution.

### MITRE ATT&CK Mapping

- T1059.001 - PowerShell (Execution)
  - Reason: PowerShell is commonly used for command and script execution.
- T1027 - Obfuscated Files or Information (Defense Evasion)
  - Reason: Encoded command usage may indicate command obfuscation.

### Detection Rule Mapping

- Suspicious PowerShell EncodedCommand Execution
  - Severity: High
  - Description: Detects PowerShell execution using encoded command indicators.
  - Log Sources: Microsoft Defender DeviceProcessEvents, Sysmon Event ID 1, Windows Security Event ID 4688
  - Reason: PowerShell execution with encoded command usage may indicate obfuscated script execution.
- PowerShell Invoke-Expression Usage
  - Severity: Medium
  - Description: Detects use of IEX or Invoke-Expression patterns.
  - Log Sources: Microsoft Defender DeviceProcessEvents, PowerShell Script Block Logs, Sysmon Event ID 1
  - Reason: IEX is commonly used to execute PowerShell content in memory.

### Detection Templates

- Suspicious PowerShell EncodedCommand
  - Type: Sigma
  - Severity: High
  - Description: Detects PowerShell execution using encoded command arguments.
  - Query:

```text
title: Suspicious PowerShell EncodedCommand
id: 00000000-0000-0000-0000-000000000024
status: experimental
description: Detects PowerShell execution using encoded command arguments.
author: Encoded Command Analyzer
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
    CommandLine|contains:
      - '-enc'
      - '-encodedcommand'
  condition: selection
falsepositives:
  - Administrative scripts
  - Software deployment tools
level: high
tags:
  - attack.execution
  - attack.t1059.001
  - attack.defense_evasion
  - attack.t1027
```

- PowerShell EncodedCommand Execution
  - Type: Microsoft Sentinel KQL
  - Severity: High
  - Description: Detects PowerShell process executions containing encoded command arguments.
  - Query:

```text
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("-enc", "-encodedcommand")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

- PowerShell Invoke-Expression Usage
  - Type: Microsoft Sentinel KQL
  - Severity: Medium
  - Description: Detects PowerShell command lines containing IEX or Invoke-Expression.
  - Query:

```text
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("iex", "invoke-expression")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```


---

