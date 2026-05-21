# Encoded Command Analyzer

![Python](https://img.shields.io/badge/Python-3.x-blue)
![License: MIT](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)
![Project Type](https://img.shields.io/badge/Project-Detection%20Engineering-red)
![Interface](https://img.shields.io/badge/Interface-CLI%20%7C%20GUI-purple)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-orange)
![Detection Mapping](https://img.shields.io/badge/Detection-Rule%20Mapping-red)
![Templates](https://img.shields.io/badge/Templates-Sigma%20%7C%20Sentinel-blue)
![YAML Templates](https://img.shields.io/badge/Templates-YAML%20Library-blue)
![Coverage](https://img.shields.io/badge/Coverage-Summary-success)
![Branding](https://img.shields.io/badge/Reports-Custom%20Branding-blue)
![Configurable Rules](https://img.shields.io/badge/Rules-Configurable-blue)
![Case Context](https://img.shields.io/badge/Case-Context-informational)
![Exports](https://img.shields.io/badge/Exports-JSON%20%7C%20CSV%20%7C%20Markdown%20%7C%20HTML-yellow)
![Decoding](https://img.shields.io/badge/Decoding-Base64%20%7C%20URL%20%7C%20Hex%20%7C%20XOR-blueviolet)
![Testing](https://img.shields.io/badge/Testing-Unittest-brightgreen)
![Packaging](https://img.shields.io/badge/Packaging-PyInstaller-lightgrey)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)

## Overview

**Encoded Command Analyzer** is a Python-based detection engineering utility for decoding and analyzing encoded command-line content.

The tool helps security analysts and detection engineers triage suspicious commands, identify signs of PowerShell abuse, detect common obfuscation patterns, map findings to MITRE ATT&CK techniques, suggest related detection rule ideas, load starter Sigma and Microsoft Sentinel KQL templates from a YAML template library, summarize detection coverage, and produce analyst-friendly investigation reports with optional case context and custom report branding.

This project started as a simple Base64 decoder and has expanded into a lightweight encoded command analysis tool with CLI support, GUI support, batch file analysis, chained decoding, compressed Base64 support, XOR Hex decoding, suspicious keyword detection, configurable keyword rules, risk scoring, MITRE ATT&CK mapping, detection rule mapping, YAML-based detection template loading, detection coverage summaries, analyst-ready exports, unit testing, Windows executable packaging, HTML report generation, optional case context enrichment, and custom report branding.

---

## Current Version

**Version 29**

### What Changed in Version 29

Version 29 adds a **YAML-based detection template library**.

Earlier versions stored external detection templates in a single JSON file. Version 29 moves detection templates into individual YAML files organized by platform and template type.

New template structure:

```text
templates/
├── sigma/
│   └── suspicious_powershell_encodedcommand.yml
└── sentinel/
    ├── powershell_encodedcommand.yml
    ├── powershell_iex_usage.yml
    ├── powershell_download_cradle.yml
    └── command_shell_execution.yml
```

This makes the project easier to maintain, easier to expand, and more aligned with real detection engineering repositories. Analysts can now add new Sigma or Microsoft Sentinel KQL templates without modifying the core Python detection logic.

Version 29 also adds:

- `template_loader.py`
- YAML template loading with `PyYAML`
- Template matching based on YAML `keywords`
- Template source file tracking through `source_file`
- Cleaner separation between detection logic and detection content

---

## Current Capabilities

- Decode standard Base64 strings
- Decode PowerShell UTF-16LE EncodedCommand values
- Decode URL-encoded strings
- Decode Hex-encoded strings
- Decode chained encoding patterns
- Decode Gzip-compressed Base64
- Decode Deflate-compressed Base64
- Decode Raw Deflate Base64
- Decode single-byte XOR Hex strings
- Rank XOR Hex candidates and return the highest-confidence result
- Analyze a single encoded string
- Analyze a batch file containing multiple encoded strings
- Identify suspicious command-line keywords
- Load suspicious keyword rules from a JSON config file
- Use fallback default keyword rules if the config file is missing or invalid
- Assign a risk level based on detected indicators
- Explain why a command may be suspicious
- Map suspicious indicators to MITRE ATT&CK techniques
- Suggest related detection rule ideas
- Identify possible log sources for detection engineering
- Load Sigma detection templates from YAML files
- Load Microsoft Sentinel KQL detection templates from YAML files
- Manage detection templates without editing Python code
- Add or modify templates under the `templates/` directory
- Match detection templates based on decoded command content
- Generate a detection coverage summary
- Summarize MITRE ATT&CK techniques across all decoded results
- Summarize detection rule ideas across all decoded results
- Summarize Sigma and Sentinel templates across all decoded results
- Add optional case context from CLI arguments
- Add optional case context directly from the GUI
- Add optional analyst notes to exported reports
- Add custom report titles to exported Markdown and HTML reports
- Add organization, team, or lab name to exported reports
- Add report classification or handling labels to exported reports
- Generate branded analyst-ready reports for portfolio or SOC-style documentation
- Export GUI-entered case context to JSON, CSV, Markdown, and HTML reports
- Export analysis results to JSON
- Export analysis results to CSV
- Export analyst triage reports to Markdown and HTML
- Generate dark-themed browser-based investigation reports
- Provide both CLI and Tkinter GUI interfaces
- Display a GUI risk banner for quick analyst review
- Unit tests for decoder logic
- Unit tests for detection logic
- Unit tests for risk scoring
- Unit tests for MITRE ATT&CK mapping
- Package the Tkinter GUI as a Windows executable
- Run the GUI without launching Python manually
- Distribute the executable through GitHub Releases

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
- Compressed payload delivery
- Chained encoding and obfuscation
- Lightweight XOR-obfuscated strings

This tool provides a simple way to decode suspicious content and quickly review indicators that may be useful during triage, detection engineering, and incident response.

---

## Supported Decoding

| Encoding Type | Status |
|---|---|
| Base64 UTF-8 | Supported |
| PowerShell UTF-16LE Base64 | Supported |
| URL Encoding | Supported |
| Hex Encoding | Supported |
| Chained Encoding | Supported |
| Gzip Base64 | Supported |
| Deflate Base64 | Supported |
| Raw Deflate Base64 | Supported |
| XOR Hex | Supported |

---

## Case Context Enrichment

The tool supports optional analyst case context fields.

Case context is **not shown by default**. It only appears in the console, GUI exports, and exported reports when explicitly provided.

Case context can be added in two ways:

1. Through CLI arguments
2. Through the Tkinter GUI case context fields

Supported case fields:

| Field | CLI Argument | GUI Field |
|---|---|---|
| Case ID | `--case-id` | Case ID |
| Analyst Name | `--analyst` | Analyst |
| Alert Source | `--alert-source` | Alert Source |
| Hostname | `--hostname` | Hostname |
| Username | `--username` | Username |
| Analyst Notes | `--notes` | Analyst Notes |

### CLI Case Context Example

```powershell
python base64_decoder.py --input "cG93ZXJzaGVsbCUyRWV4ZSUyMC1lbmMlMjBJRVg=" --export --case-id "INC-1001" --analyst "SOC Analyst" --alert-source "Microsoft Defender" --hostname "WIN-TEST01" --username "test.user" --notes "Suspicious encoded PowerShell observed in process command line."
```

### GUI Case Context

The GUI supports:

```text
Case ID
Analyst
Alert Source
Hostname
Username
Analyst Notes
```

When these fields are populated and results are exported, the case context is included in:

```text
output/analysis_result.json
output/analysis_result.csv
output/triage_report.md
output/triage_report.html
```

If the GUI fields are left blank, no case context is added.

For public examples, use generic values such as `SOC Analyst` or `Analyst Name`.

---

## Custom Report Branding

The tool supports custom report branding for exported Markdown and HTML reports.

Report branding is optional. If no custom branding is provided, the reports use the default title:

```text
Encoded Command Analyzer Triage Report
```

Custom branding can include:

| Field | CLI Argument | Purpose |
|---|---|---|
| Report Title | `--report-title` | Custom title for the exported report |
| Organization | `--organization` | Organization, team, or lab name |
| Classification | `--classification` | Handling label such as Internal Use Only |

Example:

```powershell
python base64_decoder.py --input "cG93ZXJzaGVsbCUyRWV4ZSUyMC1lbmMlMjBJRVg=" --export --report-title "Encoded PowerShell Triage Report" --organization "Detection Engineering Lab" --classification "Internal Use Only"
```

The exported Markdown and HTML reports will show:

```text
Encoded PowerShell Triage Report
Organization: Detection Engineering Lab
Classification: Internal Use Only
```

This helps produce cleaner SOC-style reports, portfolio artifacts, and professional investigation documentation.

---

## Configurable Keyword Rules

The tool supports configurable keyword rules.

Suspicious keyword logic can be managed in:

```text
config/keyword_rules.json
```

This allows analysts and detection engineers to tune keywords, scores, severities, and reasons without editing the Python detection engine directly.

Example rule:

```json
{
  "keyword": "iex",
  "severity": "High",
  "score": 3,
  "reason": "iex is commonly used in malicious or obfuscated script execution."
}
```

Each keyword rule can include:

| Field | Purpose |
|---|---|
| `keyword` | The keyword or string to search for |
| `severity` | Analyst-friendly severity label |
| `score` | Numeric score added to the risk calculation |
| `reason` | Explanation shown in the output and reports |

If the config file is missing, empty, or invalid, the tool falls back to built-in default keyword rules.

---

## MITRE ATT&CK Mapping

The tool maps suspicious keyword matches to MITRE ATT&CK techniques.

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

## Detection Rule Mapping

The tool suggests related detection ideas based on suspicious keywords found in the decoded command. This helps connect decoded artifacts to practical detection engineering opportunities.

Example decoded command:

```text
powershell.exe -enc IEX
```

Example detection rule mappings:

```text
Suspicious PowerShell EncodedCommand Execution
PowerShell Invoke-Expression Usage
```

Each detection mapping can include:

- Rule name
- Description
- Suggested severity
- Possible log sources
- Detection reason

### Current Detection Rule Ideas

| Detection Rule | Severity | Example Log Sources |
|---|---|---|
| Suspicious PowerShell EncodedCommand Execution | High | Microsoft Defender DeviceProcessEvents, Sysmon Event ID 1, Windows Security Event ID 4688 |
| PowerShell Invoke-Expression Usage | Medium | Microsoft Defender DeviceProcessEvents, PowerShell Script Block Logs, Sysmon Event ID 1 |
| PowerShell Remote Download Cradle | High | PowerShell Script Block Logs, Microsoft Defender DeviceProcessEvents, Proxy or Web Gateway Logs |
| Base64 Decoding Inside Script Content | Medium | PowerShell Script Block Logs, Microsoft Defender DeviceProcessEvents |
| Hidden PowerShell Window Execution | Medium | Microsoft Defender DeviceProcessEvents, Sysmon Event ID 1, Windows Security Event ID 4688 |
| Windows Script Host Execution | Medium | Microsoft Defender DeviceProcessEvents, Sysmon Event ID 1, Windows Security Event ID 4688 |
| Command Shell Execution | Low | Microsoft Defender DeviceProcessEvents, Sysmon Event ID 1, Windows Security Event ID 4688 |

Detection rule mappings are suggestions and should be tuned for the target environment.

---

## YAML Detection Template Library

Version 29 uses a YAML-based detection template library.

Detection templates are loaded from:

```text
templates/
```

Expected structure:

```text
templates/
├── sigma/
│   └── suspicious_powershell_encodedcommand.yml
└── sentinel/
    ├── powershell_encodedcommand.yml
    ├── powershell_iex_usage.yml
    ├── powershell_download_cradle.yml
    └── command_shell_execution.yml
```

Each YAML template can include:

| Field | Purpose |
|---|---|
| `template_name` | Name of the detection template |
| `template_type` | Template type, such as Sigma or Microsoft Sentinel KQL |
| `severity` | Suggested severity |
| `keywords` | Keywords used to match decoded content to the template |
| `description` | Description of what the template detects |
| `query` | Sigma rule body or KQL query text |

Example YAML template:

```yaml
template_name: PowerShell Invoke-Expression Usage
template_type: Microsoft Sentinel KQL
severity: Medium
keywords:
  - iex
  - invoke-expression
description: Detects PowerShell Invoke-Expression usage, commonly used in obfuscated execution chains.
query: |
  DeviceProcessEvents
  | where FileName in~ ("powershell.exe", "pwsh.exe")
  | where ProcessCommandLine has_any ("iex", "invoke-expression")
  | project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, ReportId
```

If decoded content contains one of the configured keywords, the matching detection template is included in:

```text
CLI output
output/analysis_result.json
output/analysis_result.csv
output/triage_report.md
output/triage_report.html
```

The YAML loader is implemented in:

```text
template_loader.py
```

The detection engine calls the YAML loader with:

```python
detection_templates = match_yaml_detection_templates(decoded_text)
```

This keeps the same `detection_templates` output field while changing the source of template content from a single JSON file to a structured YAML library.

### Validate YAML Templates

To validate a YAML file, run:

```powershell
python -c "import yaml; yaml.safe_load(open('templates\\sentinel\\powershell_iex_usage.yml', encoding='utf-8')); print('YAML valid')"
```

To validate all YAML templates quickly:

```powershell
python -c "import os, yaml; [yaml.safe_load(open(os.path.join(r, f), encoding='utf-8')) for r, _, fs in os.walk('templates') for f in fs if f.endswith(('.yml', '.yaml'))]; print('All YAML templates valid')"
```

---

## Detection Templates

The tool can suggest starter detection templates.

When suspicious decoded content matches known patterns, the tool can suggest templates such as:

- Sigma rules
- Microsoft Sentinel KQL queries

Example decoded command:

```text
powershell.exe -enc IEX
```

Example matched templates:

```text
Sigma: Suspicious PowerShell EncodedCommand
Microsoft Sentinel KQL: PowerShell EncodedCommand Execution
Microsoft Sentinel KQL: PowerShell Invoke-Expression Usage
```

Detection templates may include:

- Template name
- Template type
- Severity
- Description
- Query or rule body
- Source YAML file

These templates are intended as starting points and should be reviewed, tested, and tuned before production use.

---

## Detection Coverage Summary

The tool includes a detection coverage summary.

The coverage summary aggregates key detection engineering outputs across all analysis results.

It summarizes:

- MITRE ATT&CK techniques identified
- Detection rule ideas suggested
- Detection templates matched

Example coverage summary:

```text
Detection Coverage Summary
------------------------------------
MITRE Techniques Covered:
- T1059.001 - PowerShell
- T1027 - Obfuscated Files or Information

Detection Rule Ideas:
- Suspicious PowerShell EncodedCommand Execution
- PowerShell Invoke-Expression Usage

Detection Templates:
- Sigma: Suspicious PowerShell EncodedCommand
- Microsoft Sentinel KQL: PowerShell EncodedCommand Execution
- Microsoft Sentinel KQL: PowerShell Invoke-Expression Usage
```

The coverage summary appears in:

```text
CLI output
output/triage_report.md
output/triage_report.html
```

This helps analysts quickly understand which behaviors, ATT&CK techniques, and detection opportunities were identified during analysis.

---

## Suspicious Keyword Detection

The tool checks decoded content for suspicious or investigation-relevant keywords.

Default examples include:

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

Keyword behavior can be customized in:

```text
config/keyword_rules.json
```

---

## Risk Scoring

The tool assigns a risk level based on matched keyword rule scores.

| Risk Level | Score Range | Meaning |
|---|---:|---|
| None | 0 | No suspicious keywords found |
| Low | 1-2 | Minor suspicious indicators or useful investigation context |
| Medium | 3-5 | Suspicious command-line or PowerShell behavior |
| High | 6+ | Strong indicators of obfuscation, script execution, or payload activity |

Example decoded command:

```text
powershell.exe -enc IEX
```

This may be scored as **High** because it contains PowerShell execution, encoded command usage, and `IEX`.

---

## XOR Hex Decoding

The tool supports single-byte XOR Hex decoding.

It can brute-force possible XOR keys, score decoded candidates, and return the highest-confidence result.

Example XOR Hex input:

```text
534c544651504b464f4f0d465b46030e464d40036a667b
```

Expected decoded output:

```text
powershell.exe -enc IEX
```

Example result:

```text
Detected Encoding: XOR Hex Key 0x23
Risk Level: High
MITRE ATT&CK Mapping:
- T1059.001 - PowerShell
- T1027 - Obfuscated Files or Information

Detection Rule Mapping:
- Suspicious PowerShell EncodedCommand Execution
- PowerShell Invoke-Expression Usage

Detection Templates:
- Sigma: Suspicious PowerShell EncodedCommand
- Microsoft Sentinel KQL: PowerShell EncodedCommand Execution
- Microsoft Sentinel KQL: PowerShell Invoke-Expression Usage
```

XOR Hex detection is confidence-based and intended to help analysts identify suspicious strings during triage.

---

## GUI Interface

The project includes a Tkinter-based GUI that allows analysts to:

- Paste encoded command content
- Analyze a single input
- Load a batch file
- Add optional case context fields
- Add analyst notes from the GUI
- Review decoded output
- Review suspicious keyword matches
- View risk score and reasons
- Review MITRE ATT&CK mappings
- Review detection rule mappings
- Review detection templates
- Include GUI-entered case context in exported reports
- Export results to JSON, CSV, Markdown, and HTML
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

The project supports command-line arguments for automation-friendly usage.

### Analyze a Single Input

```powershell
python base64_decoder.py --input "SGVsbG8gd29ybGQ="
```

### Analyze Suspicious Chained Input

```powershell
python base64_decoder.py --input "cG93ZXJzaGVsbCUyRWV4ZSUyMC1lbmMlMjBJRVg="
```

### Analyze XOR Hex Input

```powershell
python base64_decoder.py --input "534c544651504b464f4f0d465b46030e464d40036a667b"
```

### Analyze with Optional Case Context

```powershell
python base64_decoder.py --input "cG93ZXJzaGVsbCUyRWV4ZSUyMC1lbmMlMjBJRVg=" --export --case-id "INC-1001" --analyst "SOC Analyst" --alert-source "Microsoft Defender" --hostname "WIN-TEST01" --username "test.user" --notes "Suspicious encoded PowerShell observed in process command line."
```

### Analyze with Custom Report Branding

```powershell
python base64_decoder.py --input "cG93ZXJzaGVsbCUyRWV4ZSUyMC1lbmMlMjBJRVg=" --export --report-title "Encoded PowerShell Triage Report" --organization "Detection Engineering Lab" --classification "Internal Use Only"
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
├── template_loader.py
├── config/
│   └── keyword_rules.json
├── templates/
│   ├── sigma/
│   │   └── suspicious_powershell_encodedcommand.yml
│   └── sentinel/
│       ├── powershell_encodedcommand.yml
│       ├── powershell_iex_usage.yml
│       ├── powershell_download_cradle.yml
│       └── command_shell_execution.yml
├── samples/
│   └── sample_batch.txt
├── tests/
│   ├── test_decoder_engine.py
│   └── test_detection_engine.py
├── output/
│   ├── analysis_result.json
│   ├── analysis_result.csv
│   ├── triage_report.md
│   └── triage_report.html
├── README.md
├── requirements.txt
├── LICENSE
└── .gitignore
```

Build artifacts such as `build/`, `dist/`, and `*.spec` are intentionally excluded from source control.

### File Purpose

| File | Purpose |
|---|---|
| `base64_decoder.py` | CLI entry point and command-line argument handler |
| `encoded_command_gui.py` | Tkinter GUI entry point |
| `decoder_engine.py` | Decoding logic for Base64, UTF-16LE, URL, Hex, chained decoding, compressed Base64, and XOR Hex |
| `detection_engine.py` | Suspicious keyword detection, configurable keyword loading, risk scoring, analysis logic, MITRE ATT&CK mapping, detection rule mapping, and detection template matching |
| `template_loader.py` | Loads and matches YAML-based Sigma and Microsoft Sentinel detection templates |
| `report_exporter.py` | JSON, CSV, Markdown, and HTML export functions |
| `config/keyword_rules.json` | Configurable suspicious keyword rules |
| `templates/sigma/` | YAML-based Sigma detection templates |
| `templates/sentinel/` | YAML-based Microsoft Sentinel KQL detection templates |
| `samples/` | Sample input files for testing |
| `tests/` | Unit tests for decoder and detection logic |
| `output/` | Stores exported analysis results and triage reports |
| `requirements.txt` | Python package dependencies such as `pyyaml` |

---

## Requirements

This project uses Python 3.x.

Version 29 requires `PyYAML` for YAML template loading.

Install requirements:

```powershell
pip install -r requirements.txt
```

Or install PyYAML directly:

```powershell
pip install pyyaml
```

Example `requirements.txt`:

```text
pyyaml
```

For Windows executable packaging, PyInstaller is required:

```powershell
pip install pyinstaller
```

Tested with:

```text
Python 3.x
```

---

## Testing

This project includes unit tests for the decoder and detection engines.

The tests validate:

- Base64 decoding
- PowerShell UTF-16LE decoding
- URL decoding
- Hex decoding
- Chained decoding
- Gzip Base64 decoding
- XOR Hex decoding
- Suspicious keyword detection
- Risk scoring
- MITRE ATT&CK mapping
- YAML detection template loading

Run all tests from the project root:

```powershell
python -m unittest discover -s tests
```

Expected result:

```text
OK
```

Test files are located in:

```text
tests/
├── test_decoder_engine.py
└── test_detection_engine.py
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

## Windows Executable Packaging

The project supports packaging the Tkinter GUI as a Windows executable using PyInstaller.

Install PyInstaller:

```powershell
pip install pyinstaller
```

Build the executable:

```powershell
pyinstaller --onefile --windowed --name EncodedCommandAnalyzer encoded_command_gui.py
```

The executable will be created here:

```text
dist/EncodedCommandAnalyzer.exe
```

Run the executable:

```powershell
.\dist\EncodedCommandAnalyzer.exe
```

### Packaging Notes

The following PyInstaller build artifacts are ignored by Git:

```text
build/
dist/
*.spec
```

The executable should not be committed directly to the repository. Use GitHub Releases to distribute packaged builds.

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

Detection Rule Mapping:
- Suspicious PowerShell EncodedCommand Execution
- PowerShell Invoke-Expression Usage

Detection Templates:
- Sigma: Suspicious PowerShell EncodedCommand
- Microsoft Sentinel KQL: PowerShell EncodedCommand Execution
- Microsoft Sentinel KQL: PowerShell Invoke-Expression Usage

Detection Coverage Summary:
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

Detection Rule Mapping:
- Suspicious PowerShell EncodedCommand Execution
- PowerShell Invoke-Expression Usage

Detection Templates:
- Sigma: Suspicious PowerShell EncodedCommand
- Microsoft Sentinel KQL: PowerShell EncodedCommand Execution
- Microsoft Sentinel KQL: PowerShell Invoke-Expression Usage
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

Detection Rule Mapping:
- Suspicious PowerShell EncodedCommand Execution
- PowerShell Invoke-Expression Usage

Detection Templates:
- Sigma: Suspicious PowerShell EncodedCommand
- Microsoft Sentinel KQL: PowerShell EncodedCommand Execution
- Microsoft Sentinel KQL: PowerShell Invoke-Expression Usage
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

Detection Rule Mapping:
- Suspicious PowerShell EncodedCommand Execution
- PowerShell Invoke-Expression Usage

Detection Templates:
- Sigma: Suspicious PowerShell EncodedCommand
- Microsoft Sentinel KQL: PowerShell EncodedCommand Execution
- Microsoft Sentinel KQL: PowerShell Invoke-Expression Usage
```

---

## Example: Gzip Base64 Input

You can generate a Gzip Base64 test string with Python:

```python
import base64
import gzip

text = "powershell.exe -enc IEX"

compressed = gzip.compress(text.encode("utf-8"))
encoded = base64.b64encode(compressed).decode("utf-8")

print(encoded)
```

Then analyze it:

```powershell
python base64_decoder.py --input "PASTE_GZIP_BASE64_HERE"
```

Expected result:

```text
Detected Encoding: Gzip Base64
Decoded Output:
powershell.exe -enc IEX

Risk Level: High
```

---

## Example: XOR Hex Input

Input:

```text
534c544651504b464f4f0d465b46030e464d40036a667b
```

Decoded output:

```text
powershell.exe -enc IEX
```

Example result:

```text
Detected Encoding: XOR Hex Key 0x23
Risk Level: High
MITRE ATT&CK Mapping:
- T1059.001 - PowerShell
- T1027 - Obfuscated Files or Information

Detection Rule Mapping:
- Suspicious PowerShell EncodedCommand Execution
- PowerShell Invoke-Expression Usage

Detection Templates:
- Sigma: Suspicious PowerShell EncodedCommand
- Microsoft Sentinel KQL: PowerShell EncodedCommand Execution
- Microsoft Sentinel KQL: PowerShell Invoke-Expression Usage
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
534c544651504b464f4f0d465b46030e464d40036a667b
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
output/triage_report.md
output/triage_report.html
```

Exported fields include:

- Report title
- Organization
- Classification
- Timestamp
- Case ID
- Analyst
- Alert Source
- Hostname
- Username
- Analyst Notes
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
- Detection rule mappings
- YAML detection templates
- Detection coverage summary in Markdown and HTML reports

---

## Analyst Triage Report

The generated Markdown triage report includes:

- Custom report title
- Optional organization
- Optional classification label
- Summary
- Optional case context
- Detection coverage summary
- Total results
- Highest risk level
- Highest score
- Original input
- Decoded output
- Suspicious keyword matches
- Risk score
- Risk reasons
- MITRE ATT&CK mappings
- Detection rule mappings
- YAML detection templates

The report is saved to:

```text
output/triage_report.md
```

---

## HTML Triage Report

The generated HTML report includes:

- Custom report title
- Optional report information card
- Optional organization and classification label
- Executive-style summary
- Optional case context
- Detection coverage summary
- Highest risk level
- Total result count
- Finding-by-finding breakdown
- Original input
- Decoded output
- Suspicious keyword matches
- Risk score and reasons
- MITRE ATT&CK mappings
- Detection rule mappings
- YAML detection templates
- Dark-themed browser-friendly formatting

The report is saved to:

```text
output/triage_report.html
```

Open it from PowerShell:

```powershell
start output\triage_report.html
```

---

## Analyst Workflow

```text
1. Copy suspicious encoded command from an alert.
2. Open Encoded Command Analyzer.
3. Paste the encoded value or load a batch file.
4. Add optional case context through CLI arguments or GUI fields when needed.
5. Add optional report branding when producing formal reports.
6. Run analysis.
7. Review decoded output.
8. Review suspicious keyword matches.
9. Review risk score and reasons.
10. Review MITRE ATT&CK mappings.
11. Review detection rule mappings.
12. Review matched Sigma or Sentinel YAML templates.
13. Review the detection coverage summary.
14. Export results to JSON, CSV, Markdown, or HTML.
15. Attach output to triage notes or investigation documentation.
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
- Detection rule development
- Sigma rule drafting
- Microsoft Sentinel KQL drafting
- Detection template library management
- Detection coverage review
- Branded report generation
- Portfolio demonstration for detection engineering roles
- Case documentation and analyst reporting

---

## Defensive Security Focus

This project is designed for defensive security use cases, including:

- Detection engineering
- Security operations
- Malware triage
- Incident response support
- Alert enrichment
- Analyst training
- Investigation documentation

It is not intended to execute decoded content.

---

## Roadmap

Planned upgrades:

- Version 30: Add saved GUI analyst profiles or default report settings
- Version 31: Add GUI report branding fields
- Version 32: Add YAML template validation checks
- Version 33: Add detection template metadata validation and linting

---

## Version History

### Version 29

Added YAML-based detection template library.

New files and folders:

```text
template_loader.py
templates/
├── sigma/
└── sentinel/
```

Version 29 moves detection template content into individual YAML files. This gives the project a more realistic detection engineering layout and makes templates easier to add, review, and maintain.

### Version 28

Added external detection templates through a JSON config file.

```text
config/detection_templates.json
```

Version 28 allowed Sigma and Microsoft Sentinel KQL templates to be managed outside of Python code.

### Version 27

Added custom report branding through CLI arguments:

```text
--report-title
--organization
--classification
```

### Version 26

Added GUI case context fields:

```text
Case ID
Analyst
Alert Source
Hostname
Username
Analyst Notes
```

### Version 25

Added Detection Coverage Summary.

Coverage summary includes:

- MITRE ATT&CK techniques covered
- Detection rule ideas
- Detection templates

---

## Git Commit

After updating the code, templates, and README:

```powershell
git status
git add .
git commit -m "Add YAML-based detection template library"
git push
```

---

## Disclaimer

This tool is intended for defensive security, detection engineering, malware analysis support, and security training purposes only.

Decoded content should always be reviewed carefully in a controlled environment.

Generated detection templates are starter templates and should be validated, tested, and tuned before production deployment.

---

## License

This project is licensed under the MIT License.
