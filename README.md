# Encoded Command Analyzer

![Python](https://img.shields.io/badge/Python-3.x-blue)
![License: MIT](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)
![Project Type](https://img.shields.io/badge/Project-Detection%20Engineering-red)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)

Encoded Command Analyzer is a Python-based detection engineering utility for decoding and analyzing encoded command-line content. The tool is designed to help security analysts and detection engineers triage suspicious commands, identify signs of PowerShell abuse, and produce analyst-friendly output.

The project started as a simple Base64 decoder and is being expanded into a lightweight encoded command analysis tool.

---

## Current Version

**Version 5**

---

## Features

- Decode standard Base64 strings
- Decode PowerShell UTF-16LE encoded commands
- Identify suspicious keywords commonly seen in suspicious command-line activity
- Assign a risk level based on detected keywords
- Explain why a command may be suspicious
- Export analysis results to JSON
- Export analysis results to CSV

---

## Why This Project Exists

Encoded and obfuscated commands are commonly seen during security investigations involving:

- Suspicious PowerShell execution
- EncodedCommand abuse
- Script-based payload delivery
- Command-line obfuscation
- Initial access and execution activity
- Malware triage
- SIEM and EDR alert investigation

This tool provides a simple way to decode encoded content and quickly review suspicious indicators.

---

## Supported Decoding

| Encoding Type | Status |
|---|---|
| Base64 UTF-8 | Supported |
| PowerShell UTF-16LE Base64 | Supported |
| URL Encoding | Planned |
| Hex Encoding | Planned |
| Gzip/Deflate Base64 | Planned |
| XOR Obfuscation | Planned |

---

## Suspicious Keyword Detection

The tool checks decoded content for suspicious keywords such as:

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
| Low | Minor suspicious indicators or useful context |
| Medium | Suspicious command-line or PowerShell behavior |
| High | Strong indicators of obfuscation, script execution, or payload activity |

Example decoded command:

```text
powershell.exe -enc IEX
```

This may be scored as **High** because it contains PowerShell execution, encoded command usage, and `IEX`.

---

## Project Structure

```text
encoded-command-analyzer/
│
├── base64_decoder.py
├── output/
│   ├── analysis_result.json
│   └── analysis_result.csv
├── README.md
├── LICENSE
└── .gitignore
```

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

Run the script from the project folder:

```powershell
python base64_decoder.py
```

Paste a Base64 string when prompted.

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
```

---

## Exporting Results

After analysis, the tool asks:

```text
Export results to JSON and CSV? y/n:
```

If you choose:

```text
y
```

The tool creates:

```text
output/analysis_result.json
output/analysis_result.csv
```

These files contain:

- Timestamp
- Detected encoding
- Decoded text
- Suspicious keywords
- Risk level
- Risk score
- Risk reasons

---

## Roadmap

Planned upgrades:

- Version 6: GUI using Tkinter
- Version 7: URL decoding support
- Version 8: Hex decoding support
- Version 9: Auto-detect encoding type
- Version 10: Decode chained encodings
- Version 11: Add command-line arguments
- Version 12: Add batch file analysis
- Version 13: Add detection rule mapping
- Version 14: Add MITRE ATT&CK technique mapping
- Version 15: Generate analyst triage reports

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

---

## Example Analyst Workflow

```text
1. Copy suspicious encoded command from an alert.
2. Run Encoded Command Analyzer.
3. Paste the encoded value.
4. Review decoded output.
5. Review suspicious keyword matches.
6. Review risk score and reasons.
7. Export results to JSON or CSV.
8. Attach output to triage notes or investigation documentation.
```

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

## Disclaimer

This tool is intended for defensive security, detection engineering, malware analysis support, and security training purposes only.

Decoded content should always be reviewed carefully in a controlled environment.

---

## License

This project is licensed under the MIT License.