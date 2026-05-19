# Encoded Command Analyzer Triage Report

## Summary

- Total Results: 2
- Highest Risk: High
- Highest Score: 7

---

## Finding 1

### Metadata

- Timestamp: 2026-05-19T13:53:20
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

---

## Finding 2

### Metadata

- Timestamp: 2026-05-19T13:53:20
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

---

