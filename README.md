# Encoded Command Analyzer

![Python](https://img.shields.io/badge/Python-3.x-blue)
![License: MIT](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)
![Project Type](https://img.shields.io/badge/Project-Detection%20Engineering-red)
![Interface](https://img.shields.io/badge/Interface-CLI%20%7C%20GUI-purple)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)

## Overview

**Encoded Command Analyzer** is a Python-based detection engineering utility for decoding and analyzing encoded command-line content.

The tool is designed to help security analysts and detection engineers triage suspicious commands, identify signs of PowerShell abuse, detect common obfuscation patterns, and produce analyst-friendly output for investigations.

This project started as a simple Base64 decoder and has been expanded into a lightweight encoded command analysis tool with CLI support, GUI support, chained decoding, suspicious keyword detection, risk scoring, and JSON/CSV exports.

---

## Current Version

**Version 11**

### Current Capabilities

- Decode standard Base64 strings
- Decode PowerShell UTF-16LE EncodedCommand values
- Decode URL-encoded strings
- Decode Hex-encoded strings
- Decode chained encoding patterns
- Identify suspicious command-line keywords
- Assign a risk level based on detected indicators
- Explain why a command may be suspicious
- Export analysis results to JSON
- Export analysis results to CSV
- Provide both CLI and Tkinter GUI interfaces
- Display a GUI risk banner for quick analyst review

---

## Why This Project Exists

Encoded and obfuscated commands are commonly seen during security investigations involving:

- Suspicious PowerShell execution
- EncodedCommand abuse
- Script-based payload delivery
- Command-line obfuscation
- Malware staging
- Initial access activity
- Execution and defense evasion activity
- SIEM and EDR alert investigation

This tool provides a simple way to decode suspicious content and quickly review indicators that may be useful during triage.

---

## Supported Decoding

| Encoding Type | Status |
|---|---|
| Base64 UTF-8 | Supported |
| PowerShell UTF-16LE Base64 | Supported |
| URL Encoding | Supported |
| Hex Encoding | Supported |
| Chained Encoding | Supported |
| Gzip/Deflate Base64 | Planned |
| XOR Obfuscation | Planned |
| Batch File Analysis | Planned |

---

## Suspicious Keyword Detection

The tool checks decoded content for suspicious or investigation-relevant keywords such as:

```text
powershell
-enc
-encodedcommand
iex
invoke-expression
downloadstring
frombase64string
webclient
start-process
cmd.exe
http
https
bypass
hidden
nop
wscript
cscript
```

Finding one of these keywords does not automatically mean the command is malicious. The results should be reviewed in context by an analyst.

---

## Risk Scoring

The tool assigns a risk level based on suspicious keyword matches.

| Risk Level | Meaning |
|---|---|
| None | No suspicious keywords found |
| Low | Minor suspicious indicators or useful investigation context |
| Medium | Suspicious command-line or PowerShell behavior |
| High | Strong indicators of obfuscation, script execution, or payload activity |

Example decoded command:

```text
powershell.exe -enc IEX
```

This may be scored as **High** because it contains PowerShell execution, encoded command usage, and `IEX`.

---

## GUI Interface

The project includes a Tkinter-based GUI that allows analysts to:

- Paste encoded command content
- Analyze the input
- Review decoded output
- Review suspicious keyword matches
- View risk score and reasons
- Export results to JSON and CSV
- Clear and rerun analysis

The GUI includes a color-coded risk banner:

| Risk Level | Banner Meaning |
|---|---|
| High | Strong suspicious indicators detected |
| Medium | Suspicious behavior detected |
| Low | Minor indicators detected |
| None | No suspicious keywords detected |

---

## Project Structure

```text
encoded-command-analyzer/
│
├── base64_decoder.py
├── encoded_command_gui.py
├── decoder_engine.py
├── detection_engine.py
├── report_exporter.py
├── output/
│   ├── analysis_result.json
│   └── analysis_result.csv
├── README.md
├── LICENSE
└── .gitignore
```

### File Purpose

| File | Purpose |
|---|---|
| `base64_decoder.py` | CLI entry point |
| `encoded_command_gui.py` | Tkinter GUI entry point |
| `decoder_engine.py` | Decoding logic for Base64, UTF-16LE, URL, Hex, and chained decoding |
| `detection_engine.py` | Suspicious keyword detection, scoring, and analysis logic |
| `report_exporter.py` | JSON and CSV export functions |
| `output/` | Stores exported analysis results |

---

## Requirements

This project currently uses Python standard libraries only.

No external packages are required.

Tested with:

```text
Python 3.x
```

---

## Usage

### Run the CLI Version

From the project folder:

```powershell
python base64_decoder.py
```

Paste an encoded string when prompted.

---

### Run the GUI Version

From the project folder:

```powershell
python encoded_command_gui.py
```

Paste an encoded string into the input box and click **Analyze**.

---

## Example: Clean Base64 Input

Input:

```text
SGVsbG8gd29ybGQ=
```

Decoded output:

```text
Hello world
```

Expected result:

```text
Risk Level: None
Score: 0
No suspicious keywords found.
```

---

## Example: PowerShell UTF-16LE EncodedCommand Input

Input:

```text
cABvAHcAZQByAHMAaABlAGwAbAAuAGUAeABlACAALQBlAG4AYwAgAEkARQBYAA==
```

Decoded output:

```text
powershell.exe -enc IEX
```

Example result:

```text
Suspicious keywords found:
- powershell
- -enc
- iex

Risk Level: High
Score: 7
```

---

## Example: URL-Encoded Input

Input:

```text
powershell%2Eexe%20-enc%20IEX
```

Decoded output:

```text
powershell.exe -enc IEX
```

Example result:

```text
Risk Level: High
```

---

## Example: Hex-Encoded Input

Input:

```text
706f7765727368656c6c2e657865202d656e6320494558
```

Decoded output:

```text
powershell.exe -enc IEX
```

Example result:

```text
Risk Level: High
```

---

## Example: Chained Encoding

Input:

```text
cG93ZXJzaGVsbCUyRWV4ZSUyMC1lbmMlMjBJRVg=
```

Decode flow:

```text
Level 1: Base64 UTF-8
powershell%2Eexe%20-enc%20IEX

Level 2: URL
powershell.exe -enc IEX
```

Example final result:

```text
Risk Level: High
Score: 7
```

---

## Exporting Results

After analysis, the tool can export results to:

```text
output/analysis_result.json
output/analysis_result.csv
```

Exported fields include:

- Timestamp
- Detected encoding
- Decode level
- Source encoding
- Decoded text
- Suspicious keywords
- Risk level
- Risk score
- Risk reasons

---

## Analyst Workflow

```text
1. Copy suspicious encoded command from an alert.
2. Open Encoded Command Analyzer.
3. Paste the encoded value.
4. Run analysis.
5. Review decoded output.
6. Review suspicious keyword matches.
7. Review risk score and reasons.
8. Export results to JSON or CSV.
9. Attach output to triage notes or investigation documentation.
```

---

## Detection Engineering Use Cases

This project can support:

- Alert triage
- Encoded PowerShell investigation
- Malware analysis support
- SOC analyst training
- Detection engineering testing
- SIEM rule validation
- Suspicious command-line review
- Investigation enrichment
- Portfolio demonstration for detection engineering roles

---

## Defensive Security Focus

This project is designed for defensive security use cases, including:

- Detection engineering
- Security operations
- Malware triage
- Incident response support
- Alert enrichment
- Analyst training

It is not intended to execute decoded content.

---

## Roadmap

Planned upgrades:

- Version 12: Batch file analysis
- Version 13: Add command-line arguments
- Version 14: Add MITRE ATT&CK technique mapping
- Version 15: Add detection rule mapping
- Version 16: Generate analyst triage reports
- Version 17: Add Gzip/Deflate Base64 support
- Version 18: Add XOR decode helper
- Version 19: Add unit tests
- Version 20: Package as an executable

---

## Disclaimer

This tool is intended for defensive security, detection engineering, malware analysis support, and security training purposes only.

Decoded content should always be reviewed carefully in a controlled environment.

---

## License

This project is licensed under the MIT License.