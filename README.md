# Encoded Command Analyzer

![Python](https://img.shields.io/badge/Python-3.x-blue)
![License: MIT](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)
![Project Type](https://img.shields.io/badge/Project-Detection%20Engineering-red)
![Interface](https://img.shields.io/badge/Interface-CLI%20%7C%20GUI-purple)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-orange)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)

## Overview

**Encoded Command Analyzer** is a Python-based detection engineering utility for decoding and analyzing encoded command-line content.

The tool is designed to help security analysts and detection engineers triage suspicious commands, identify signs of PowerShell abuse, detect common obfuscation patterns, map findings to MITRE ATT&CK techniques, and produce analyst-friendly output for investigations.

This project started as a simple Base64 decoder and has been expanded into a lightweight encoded command analysis tool with CLI support, GUI support, batch file analysis, chained decoding, suspicious keyword detection, risk scoring, MITRE ATT&CK mapping, and JSON/CSV exports.

---

## Current Version

**Version 14**

### Current Capabilities

- Decode standard Base64 strings
- Decode PowerShell UTF-16LE EncodedCommand values
- Decode URL-encoded strings
- Decode Hex-encoded strings
- Decode chained encoding patterns
- Analyze a single encoded string
- Analyze a batch file containing multiple encoded strings
- Identify suspicious command-line keywords
- Assign a risk level based on detected indicators
- Explain why a command may be suspicious
- Map suspicious indicators to MITRE ATT&CK techniques
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

---

## MITRE ATT&CK Mapping

Version 14 adds MITRE ATT&CK mapping based on suspicious keyword matches.

The tool can currently map findings to techniques such as:

| Keyword / Indicator | MITRE Technique | Tactic |
|---|---|---|
| `powershell` | T1059.001 - PowerShell | Execution |
| `iex` | T1059.001 - PowerShell | Execution |
| `invoke-expression` | T1059.001 - PowerShell | Execution |
| `cmd.exe` | T1059.003 - Windows Command Shell | Execution |
| `wscript` | T1059.005 - Visual Basic | Execution |
| `cscript` | T1059.005 - Visual Basic | Execution |
| `-enc` | T1027 - Obfuscated Files or Information | Defense Evasion |
| `-encodedcommand` | T1027 - Obfuscated Files or Information | Defense Evasion |
| `frombase64string` | T1027 - Obfuscated Files or Information | Defense Evasion |
| `bypass` | T1562.001 - Disable or Modify Tools | Defense Evasion |
| `hidden` | T1564.003 - Hidden Window | Defense Evasion |
| `downloadstring` | T1105 - Ingress Tool Transfer | Command and Control |
| `webclient` | T1105 - Ingress Tool Transfer | Command and Control |
| `http` | T1105 - Ingress Tool Transfer | Command and Control |
| `https` | T1105 - Ingress Tool Transfer | Command and Control |

MITRE mappings are based on keyword indicators and should be reviewed in context by an analyst.

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
- Analyze a single input
- Load a batch file
- Review decoded output
- Review suspicious keyword matches
- View risk score and reasons
- Review MITRE ATT&CK mappings
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

## CLI Interface

The project also supports command-line arguments for automation-friendly usage.

### Analyze a Single Input

```powershell
python base64_decoder.py --input "SGVsbG8gd29ybGQ="
```

### Analyze a Batch File

```powershell
python base64_decoder.py --file samples\sample_batch.txt
```

### Analyze and Export Results

```powershell
python base64_decoder.py --file samples\sample_batch.txt --export
```

### Launch the GUI

```powershell
python base64_decoder.py --gui
```

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
├── samples/
│   └── sample_batch.txt
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
| `base64_decoder.py` | CLI entry point and command-line argument handler |
| `encoded_command_gui.py` | Tkinter GUI entry point |
| `decoder_engine.py` | Decoding logic for Base64, UTF-16LE, URL, Hex, and chained decoding |
| `detection_engine.py` | Suspicious keyword detection, risk scoring, analysis logic, and MITRE ATT&CK mapping |
| `report_exporter.py` | JSON and CSV export functions |
| `samples/` | Sample input files for testing |
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
python base64_decoder.py --input "SGVsbG8gd29ybGQ="
```

### Run the GUI Version

From the project folder:

```powershell
python encoded_command_gui.py
```

Or launch the GUI from the CLI:

```powershell
python base64_decoder.py --gui
```

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

MITRE ATT&CK Mapping:
- T1059.001 - PowerShell
- T1027 - Obfuscated Files or Information
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
MITRE ATT&CK Mapping:
- T1059.001 - PowerShell
- T1027 - Obfuscated Files or Information
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
MITRE ATT&CK Mapping:
- T1059.001 - PowerShell
- T1027 - Obfuscated Files or Information
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

MITRE ATT&CK Mapping:
- T1059.001 - PowerShell
- T1027 - Obfuscated Files or Information
```

---

## Example: Batch File Analysis

Create a text file with one encoded value per line:

```text
SGVsbG8gd29ybGQ=
cABvAHcAZQByAHMAaABlAGwAbAAuAGUAeABlACAALQBlAG4AYwAgAEkARQBYAA==
powershell%2Eexe%20-enc%20IEX
706f7765727368656c6c2e657865202d656e6320494558
cG93ZXJzaGVsbCUyRWV4ZSUyMC1lbmMlMjBJRVg=
```

Run:

```powershell
python base64_decoder.py --file samples\sample_batch.txt
```

Optional export:

```powershell
python base64_decoder.py --file samples\sample_batch.txt --export
```

---

## Exporting Results

The tool can export results to:

```text
output/analysis_result.json
output/analysis_result.csv
```

Exported fields include:

- Timestamp
- Batch item
- Source file
- Original input
- Detected encoding
- Decode level
- Source encoding
- Decoded text
- Suspicious keywords
- Risk level
- Risk score
- Risk reasons
- MITRE ATT&CK mappings

---

## Analyst Workflow

```text
1. Copy suspicious encoded command from an alert.
2. Open Encoded Command Analyzer.
3. Paste the encoded value or load a batch file.
4. Run analysis.
5. Review decoded output.
6. Review suspicious keyword matches.
7. Review risk score and reasons.
8. Review MITRE ATT&CK mappings.
9. Export results to JSON or CSV.
10. Attach output to triage notes or investigation documentation.
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
- ATT&CK mapping practice
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

- Version 15: Generate analyst triage reports
- Version 16: Add Gzip/Deflate Base64 support
- Version 17: Add XOR decode helper
- Version 18: Add unit tests
- Version 19: Package as an executable
- Version 20: Add detection rule mapping

---

## Disclaimer

This tool is intended for defensive security, detection engineering, malware analysis support, and security training purposes only.

Decoded content should always be reviewed carefully in a controlled environment.

---

## License

This project is licensed under the MIT License.