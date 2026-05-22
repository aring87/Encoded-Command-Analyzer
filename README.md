# Encoded Command Analyzer

![Python](https://img.shields.io/badge/Python-3.x-blue)
![License: MIT](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)
![Project Type](https://img.shields.io/badge/Project-Detection%20Engineering-red)
![Interface](https://img.shields.io/badge/Interface-CLI%20%7C%20GUI-purple)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-orange)
![Detection Mapping](https://img.shields.io/badge/Detection-Rule%20Mapping-red)
![Templates](https://img.shields.io/badge/Templates-Sigma%20%7C%20Sentinel-blue)
![YAML Templates](https://img.shields.io/badge/Templates-YAML-blue)
![Coverage](https://img.shields.io/badge/Coverage-Summary-success)
![Branding](https://img.shields.io/badge/Reports-Custom%20Branding-blue)
![GUI Branding](https://img.shields.io/badge/GUI-Report%20Branding-blueviolet)
![Analyst Profile](https://img.shields.io/badge/Profile-Analyst%20Defaults-informational)
![Configurable Rules](https://img.shields.io/badge/Rules-Configurable-blue)
![Case Context](https://img.shields.io/badge/Case-Context-informational)
![Exports](https://img.shields.io/badge/Exports-JSON%20%7C%20CSV%20%7C%20Markdown%20%7C%20HTML-yellow)
![Decoding](https://img.shields.io/badge/Decoding-Base64%20%7C%20URL%20%7C%20Hex%20%7C%20XOR-blueviolet)
![Testing](https://img.shields.io/badge/Testing-Unittest-brightgreen)
![Packaging](https://img.shields.io/badge/Packaging-PyInstaller-lightgrey)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)

## Overview

**Encoded Command Analyzer** is a Python-based detection engineering utility for decoding and analyzing encoded command-line content.

The tool is designed to help security analysts, SOC analysts, malware triage analysts, and detection engineers decode suspicious commands, identify signs of PowerShell abuse, detect obfuscation patterns, map findings to MITRE ATT&CK techniques, suggest related detection rule ideas, load Sigma and Microsoft Sentinel KQL templates from a YAML template library, summarize detection coverage, and generate analyst-friendly reports.

This project started as a simple Base64 decoder and has expanded into a lightweight encoded command analysis tool with CLI support, Tkinter GUI support, batch analysis, chained decoding, compressed Base64 support, XOR Hex decoding, suspicious keyword detection, configurable keyword rules, risk scoring, MITRE ATT&CK mapping, detection rule mapping, YAML-based detection templates, detection coverage summaries, saved analyst profile defaults, GUI report branding fields, analyst-ready exports, unit testing, Windows executable packaging, Markdown report generation, HTML report generation, optional case context enrichment, and custom report branding.

---

## Current Version

**Version 31**

---

## What's New in Version 31

Version 31 adds **GUI-based report branding fields**.

Report branding was previously supported through CLI arguments and analyst profile defaults. Version 31 brings that same capability directly into the Tkinter GUI, allowing analysts to customize exported reports without using command-line options.

New GUI report branding fields:

- Report Title
- Organization
- Classification

When populated in the GUI, these values are included in exported Markdown and HTML triage reports.

Example GUI report branding:

```text
Report Title: Encoded PowerShell Triage Report
Organization: RingForge Lab
Classification: TLP:AMBER
```

Example exported report header:

```markdown
# Encoded PowerShell Triage Report

**Organization:** RingForge Lab

**Classification:** TLP:AMBER
```

This improves the GUI workflow for analysts who want clean, branded reports for investigations, portfolio artifacts, detection engineering labs, or SOC-style documentation.

---

## Version 31 Capabilities

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
- Load Microsoft Sentinel KQL templates from YAML files
- Organize detection templates by platform under `templates/`
- Match decoded content to YAML detection templates using keywords
- Include matched detection templates in CLI output and exported reports
- Generate a detection coverage summary
- Summarize MITRE ATT&CK techniques across all decoded results
- Summarize detection rule ideas across all decoded results
- Summarize Sigma and Sentinel templates across all decoded results
- Add optional case context from CLI arguments
- Add optional case context directly from the GUI
- Add optional analyst notes to exported reports
- Load saved analyst defaults from `config/analyst_profile.json`
- Load saved organization defaults from `config/analyst_profile.json`
- Load saved classification defaults from `config/analyst_profile.json`
- Load saved default report title from `config/analyst_profile.json`
- Override saved analyst profile defaults with CLI arguments
- Add custom report titles to exported Markdown and HTML reports
- Add organization, team, or lab name to exported reports
- Add report classification or handling labels to exported reports
- Add report branding fields directly from the Tkinter GUI
- Add custom report title from the GUI
- Add organization, team, or lab name from the GUI
- Add report classification or handling label from the GUI
- Export GUI-entered report branding to Markdown and HTML reports
- Remove blank Case Context fields from Markdown and HTML reports
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
- Execution activity
- Defense evasion activity
- SIEM and EDR alert investigation
- Compressed payload delivery
- Chained encoding and obfuscation
- Lightweight XOR-obfuscated strings

This tool provides a simple way to decode suspicious content and quickly review indicators that may be useful during triage, detection engineering, malware analysis support, and incident response.

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

Case context is optional and can be provided in two ways:

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

Blank case context fields are automatically removed from Markdown and HTML reports. This keeps reports cleaner and prevents empty fields from appearing.

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

If fields are left blank, they are not shown in Markdown or HTML reports.

---

## Analyst Profile Defaults

Version 30 added saved analyst profile defaults.

Analyst profile settings are loaded from:

```text
config/analyst_profile.json
```

Example profile:

```json
{
  "analyst": "SOC Analyst",
  "organization": "Detection Engineering Lab",
  "classification": "Internal Use Only",
  "default_report_title": "Encoded Command Analyzer Triage Report"
}
```

These values can be used automatically when running exports.

Supported analyst profile fields:

| Field | Purpose |
|---|---|
| `analyst` | Default analyst name |
| `organization` | Default organization, team, or lab name |
| `classification` | Default classification or handling label |
| `default_report_title` | Default Markdown and HTML report title |

CLI arguments override analyst profile defaults.

Priority order:

```text
1. CLI argument
2. analyst_profile.json default
3. built-in fallback default
```

Example:

```powershell
python base64_decoder.py --input "SGVsbG8gd29ybGQ=" --export --analyst "Adam Ring" --organization "RingForge Lab" --classification "TLP:AMBER"
```

This uses the CLI-provided values instead of the saved profile defaults.

---

## Custom Report Branding

The tool supports custom report branding for exported Markdown and HTML reports.

Report branding is optional. If no custom branding is provided, the reports use the default title:

```text
Encoded Command Analyzer Triage Report
```

Custom branding can be provided in three ways:

1. Through CLI arguments
2. Through saved analyst profile defaults in `config/analyst_profile.json`
3. Through the Tkinter GUI report branding fields

Custom branding can include:

| Field | CLI Argument | GUI Field | Analyst Profile Key | Purpose |
|---|---|---|---|---|
| Report Title | `--report-title` | Report Title | `default_report_title` | Custom title for the exported report |
| Organization | `--organization` | Organization | `organization` | Organization, team, or lab name |
| Classification | `--classification` | Classification | `classification` | Handling label such as Internal Use Only or TLP:AMBER |

### CLI Report Branding Example

```powershell
python base64_decoder.py --input "cG93ZXJzaGVsbCUyRWV4ZSUyMC1lbmMlMjBJRVg=" --export --report-title "Encoded PowerShell Triage Report" --organization "Detection Engineering Lab" --classification "Internal Use Only"
```

The exported Markdown and HTML reports will show:

```text
Encoded PowerShell Triage Report
Organization: Detection Engineering Lab
Classification: Internal Use Only
```

### GUI Report Branding Example

The GUI includes a Report Branding section with the following fields:

```text
Report Title
Organization
Classification
```

Example values:

```text
Report Title: Encoded PowerShell Triage Report
Organization: RingForge Lab
Classification: TLP:AMBER
```

When results are exported, the Markdown and HTML reports include:

```markdown
# Encoded PowerShell Triage Report

**Organization:** RingForge Lab

**Classification:** TLP:AMBER
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

Version 29 added a YAML-based detection template library.

Detection templates are now organized under:

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

This allows detection engineers to add, remove, or modify Sigma and Microsoft Sentinel KQL templates without editing the Python source code.

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

---

## Detection Templates

The tool can suggest starter detection templates when suspicious decoded content matches known patterns.

Supported template types include:

- Sigma
- Microsoft Sentinel KQL

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

These templates are intended as starting points and should be reviewed, tested, and tuned before production use.

---

## Detection Coverage Summary

The tool includes a detection coverage summary.

The coverage summary aggregates key detection engineering outputs across all analysis results.

It summarizes:

- MITRE ATT&CK techniques identified
- Detection rule ideas suggested
- Detection templates generated

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
- Add custom report title from the GUI
- Add organization or lab name from the GUI
- Add classification or handling label from the GUI
- Review decoded output
- Review suspicious keyword matches
- View risk score and reasons
- Review MITRE ATT&CK mappings
- Review detection rule mappings
- Review detection templates
- Include GUI-entered case context in exported reports
- Export GUI-entered branding to Markdown and HTML reports
- Export results to JSON, CSV, Markdown, and HTML
- Clear and rerun analysis

The GUI includes a color-coded risk banner:

| Risk Level | Banner Meaning |
|---|---|
| High | Strong suspicious indicators detected |
| Medium | Suspicious behavior detected |
| Low | Minor indicators detected |
| None | No suspicious keywords detected |

The GUI includes a dedicated **Report Branding** section. These fields allow analysts to customize the report title, organization, and classification label before exporting results. This provides feature parity with CLI-based report branding while keeping the workflow analyst-friendly.

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

### Analyze with CLI Override of Analyst Profile Defaults

```powershell
python base64_decoder.py --input "SGVsbG8gd29ybGQ=" --export --analyst "Adam Ring" --organization "RingForge Lab" --classification "TLP:AMBER"
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

Or:

```powershell
python encoded_command_gui.py
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
├── profile_loader.py
├── config/
│   ├── keyword_rules.json
│   └── analyst_profile.json
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
├── LICENSE
└── .gitignore
```

Build artifacts such as `build/`, `dist/`, and `*.spec` are intentionally excluded from source control.

---

## File Purpose

| File | Purpose |
|---|---|
| `base64_decoder.py` | CLI entry point and command-line argument handler |
| `encoded_command_gui.py` | Tkinter GUI entry point, including case context and GUI report branding fields |
| `decoder_engine.py` | Decoding logic for Base64, UTF-16LE, URL, Hex, chained decoding, compressed Base64, and XOR Hex |
| `detection_engine.py` | Suspicious keyword detection, configurable keyword loading, risk scoring, analysis logic, MITRE ATT&CK mapping, detection rule mapping, and YAML detection template matching |
| `report_exporter.py` | JSON, CSV, Markdown, and HTML export functions, including cleaned case context and branded report output |
| `template_loader.py` | Loads YAML-based Sigma and Microsoft Sentinel detection templates |
| `profile_loader.py` | Loads saved analyst profile defaults from `config/analyst_profile.json` |
| `config/keyword_rules.json` | Configurable suspicious keyword rules |
| `config/analyst_profile.json` | Saved analyst name, organization, classification, and default report title values |
| `templates/` | YAML-based detection template library |
| `samples/` | Sample input files for testing |
| `tests/` | Unit tests for decoder and detection logic |
| `output/` | Stores exported analysis results and triage reports |

---

## Requirements

This project uses Python 3.x.

Required external packages:

```text
pyyaml
```

Install requirements:

```powershell
pip install pyyaml
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
No MITRE techniques identified.
No detection rule ideas identified.
No detection templates identified.
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
- Detection templates
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
- Detection templates

Blank case context fields are automatically removed.

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
- Detection templates
- Dark-themed browser-friendly formatting

Blank case context fields are automatically removed.

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
2. Open Encoded Command Analyzer through the CLI or GUI.
3. Paste the encoded value or load a batch file.
4. Add optional case context through CLI arguments or GUI fields when needed.
5. Add optional report branding through CLI arguments, analyst profile defaults, or GUI fields.
6. Run analysis.
7. Review decoded output.
8. Review suspicious keyword matches.
9. Review risk score and reasons.
10. Review MITRE ATT&CK mappings.
11. Review detection rule mappings.
12. Review suggested Sigma or Sentinel detection templates.
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
- YAML detection template management
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

## Version History

### Version 31

Added GUI report branding fields.

New GUI fields:

- Report Title
- Organization
- Classification

These values are exported into Markdown and HTML reports when populated in the GUI.

Version 31 improves feature parity between CLI and GUI workflows by allowing analysts to generate branded reports directly from the graphical interface.

### Version 30

Added saved analyst profile defaults.

New file:

```text
config/analyst_profile.json
```

New loader:

```text
profile_loader.py
```

Version 30 supports saved defaults for:

- Analyst
- Organization
- Classification
- Default report title

CLI arguments override saved profile defaults.

Version 30 also improved report output by removing blank Case Context fields from Markdown and HTML reports and fixing analyst notes handling in CSV, Markdown, and HTML exports.

### Version 29

Added YAML-based detection template library.

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

Detection templates are now loaded from YAML files instead of being stored in a single JSON configuration file.

### Version 28

Added external detection template support.

Detection templates were loaded from:

```text
config/detection_templates.json
```

This allowed Sigma and Microsoft Sentinel KQL templates to be modified without editing Python source code.

### Version 27

Added custom report branding through CLI.

New CLI arguments:

- `--report-title`
- `--organization`
- `--classification`

Markdown and HTML reports show:

- Report Title
- Organization
- Classification

### Version 26

Added GUI case context fields.

Fields:

- Case ID
- Analyst
- Alert Source
- Hostname
- Username
- Analyst Notes

These export to:

- JSON
- CSV
- Markdown
- HTML

### Version 25

Added Detection Coverage Summary.

Coverage summary includes:

- MITRE Techniques Covered
- Detection Rule Ideas
- Detection Templates

It appears in:

- CLI output
- Markdown reports
- HTML reports

### Earlier Versions

Earlier versions added:

- Base64 decoding
- UTF-8 and UTF-16LE handling
- Suspicious keyword detection
- Tkinter GUI support
- Batch file analysis
- URL decoding
- Hex decoding
- Chained decoding
- Risk scoring
- MITRE ATT&CK mapping
- Detection rule ideas
- JSON export
- CSV export
- Markdown export
- HTML export
- XOR Hex decoding
- Gzip and Deflate Base64 decoding

---

## Roadmap

Planned upgrades:

- Version 32: Add template validation checks
- Version 33: Add GUI analyst profile loading and save profile option
- Version 34: Add export folder selection
- Version 35: Add detection template editor or viewer

---

## Disclaimer

This tool is intended for defensive security, detection engineering, malware analysis support, and security training purposes only.

Decoded content should always be reviewed carefully in a controlled environment.

Generated detection templates are starter templates and should be validated, tested, and tuned before production deployment.

---

## License

This project is licensed under the MIT License.