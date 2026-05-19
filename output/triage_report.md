# Encoded Command Analyzer Triage Report

## Summary

- Total Results: 2
- Highest Risk: High
- Highest Score: 7

---

## Finding 1

### Metadata

- Timestamp: 2026-05-19T18:18:41
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

---

## Finding 2

### Metadata

- Timestamp: 2026-05-19T18:18:41
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

---

