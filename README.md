ChatGPT







































its still deleting

im talking baout here

now this will be my github home how do i create it


PS C:\encoded_command_analyzer> git branch -M main
PS C:\encoded_command_analyzer> git remote add origin https://github.com/aring87/encoded-command-analyzer.git
PS C:\encoded_command_analyzer> git push -u origin main
To https://github.com/aring87/encoded-command-analyzer.git
 ! [rejected]        main -> main (fetch first)
error: failed to push some refs to 'https://github.com/aring87/encoded-command-analyzer.git'
hint: Updates were rejected because the remote contains work that you do not
hint: have locally. This is usually caused by another repository pushing to
hint: the same ref. If you want to integrate the remote changes, use
hint: 'git pull' before pushing again.
hint: See the 'Note about fast-forwards' in 'git push --help' for details.
PS C:\encoded_command_analyzer>


image.png
image.png
why does it say UTE-8 and UTE-16

i dont have a encoded command gui script yet. this is what i have so far

Thought for a couple of seconds
That is close. The tool is finding the correct answer, but it is still showing one noisy XOR candidate:

XOR Hex Key 0x03
ENC iexELL♫EXE
For XOR brute force, that can happen because some wrong keys produce partial readable-looking strings. The best fix is: only return the highest-confidence XOR result instead of every possible match.

Replace your entire decode_xor_hex() function in decoder_engine.py with this version:

def decode_xor_hex(encoded_text):
    try:
        cleaned_text = encoded_text.strip().replace(" ", "").replace("0x", "")

        if len(cleaned_text) % 2 != 0:
            return []

        if not all(character in "0123456789abcdefABCDEF" for character in cleaned_text):
            return []

        encoded_bytes = bytes.fromhex(cleaned_text)
        candidates = []

        for key in range(1, 256):
            decoded_bytes = bytes(byte ^ key for byte in encoded_bytes)
            decoded_text = decoded_bytes.decode("utf-8", errors="ignore")
            lowered_text = decoded_text.lower()

            matched_hints = []

            for hint in SUSPICIOUS_HINTS:
                if hint in lowered_text:
                    matched_hints.append(hint)

            if not matched_hints:
                continue

            if not looks_readable(decoded_text):
                continue

            confidence_score = 0

            if "powershell" in lowered_text:
                confidence_score += 5

            if "powershell.exe" in lowered_text:
                confidence_score += 5

            if "-enc" in lowered_text or "-encodedcommand" in lowered_text:
                confidence_score += 4

            if "iex" in lowered_text:
                confidence_score += 3

            if "cmd.exe" in lowered_text:
                confidence_score += 3

            if "http" in lowered_text or "https" in lowered_text:
                confidence_score += 2

            # Penalize weird control characters or unreadable output
            weird_characters = 0

            for character in decoded_text:
                if not character.isprintable() and character not in "\r\n\t":
                    weird_characters += 1

            confidence_score -= weird_characters * 2

            if confidence_score >= 7:
                candidates.append({
                    "encoding": f"XOR Hex Key 0x{key:02X}",
                    "decoded_text": decoded_text,
                    "confidence_score": confidence_score
                })

        if not candidates:
            return []

        highest_score = max(candidate["confidence_score"] for candidate in candidates)

        best_candidates = []

        for candidate in candidates:
            if candidate["confidence_score"] == highest_score:
                candidate.pop("confidence_score", None)
                best_candidates.append(candidate)

        return best_candidates

    except Exception:
        return []
Now test again:

python base64_decoder.py --input "534c544651504b464f4f0d465b46030e464d40036a667b"
You should now only see the strong result:

Detected Encoding: XOR Hex Key 0x23

Decoded Output:
powershell.exe -enc IEX
Then commit it:

git status
git add .
git commit -m "Improve XOR hex result ranking"
git push
What we changed: instead of showing every XOR key that kind of works, the tool now ranks candidates and only returns the best one. That makes the output much cleaner for analyst triage.


PS C:\encoded_command_analyzer> python base64_decoder.py --input "534c544651504b464f4f0d465b46030e464d40036a667b"
====================================
Timestamp: 2026-05-19T15:29:49
Detected Encoding: XOR Hex Key 0x03
Decode Level: 1

Decoded Output:
------------------------------------
ENC iexELL♫EXE

Suspicious Keyword Check:
------------------------------------
- powershell
- iex

Risk Score:
------------------------------------
Risk Level: Medium
Score: 5

Reasons:
- powershell may indicate suspicious command-line or PowerShell behavior.
- iex is commonly used in malicious or obfuscated script execution.

MITRE ATT&CK Mapping:
------------------------------------
- T1059.001 - PowerShell (Execution)
  Reason: PowerShell is commonly used for command and script execution.

====================================
Timestamp: 2026-05-19T15:29:49
Detected Encoding: XOR Hex Key 0x23
Decode Level: 1

Decoded Output:
------------------------------------
powershell.exe -enc IEX

Suspicious Keyword Check:
------------------------------------
- powershell
- -enc
- iex

Risk Score:
------------------------------------
Risk Level: High
Score: 7

Reasons:
- powershell may indicate suspicious command-line or PowerShell behavior.
- -enc may indicate suspicious command-line or PowerShell behavior.
- iex is commonly used in malicious or obfuscated script execution.

MITRE ATT&CK Mapping:
------------------------------------
- T1059.001 - PowerShell (Execution)
  Reason: PowerShell is commonly used for command and script execution.
- T1027 - Obfuscated Files or Information (Defense Evasion)
  Reason: Encoded command usage may indicate command obfuscation.

====================================
Analysis Summary
====================================
Total Results: 2
Highest Risk: High
Highest Score: 7
====================================
PS C:\encoded_command_analyzer> python base64_decoder.py --input "534c544651504b464f4f0d465b46030e464d40036a667b"
====================================
Timestamp: 2026-05-19T15:30:55
Detected Encoding: XOR Hex Key 0x23
Decode Level: 1

Decoded Output:
------------------------------------
powershell.exe -enc IEX

Suspicious Keyword Check:
------------------------------------
- powershell
- -enc
- iex

Risk Score:
------------------------------------
Risk Level: High
Score: 7

Reasons:
- powershell may indicate suspicious command-line or PowerShell behavior.
- -enc may indicate suspicious command-line or PowerShell behavior.
- iex is commonly used in malicious or obfuscated script execution.

MITRE ATT&CK Mapping:
------------------------------------
- T1059.001 - PowerShell (Execution)
  Reason: PowerShell is commonly used for command and script execution.
- T1027 - Obfuscated Files or Information (Defense Evasion)
  Reason: Encoded command usage may indicate command obfuscation.

====================================
Analysis Summary
====================================
Total Results: 1
Highest Risk: High
Highest Score: 7
====================================
PS C:\encoded_command_analyzer>

Perfect — that second run is exactly what we wanted.

Now Version 17 is working cleanly:

Detected Encoding: XOR Hex Key 0x23
Decoded Output: powershell.exe -enc IEX
Risk Level: High
Total Results: 1
Go ahead and commit this version:

git status
git add .
git commit -m "Add XOR hex decoding support"
git push
Then update the README for Version 17 before moving on:

git status
Next phase after the README should be Version 18: unit tests, because your project is big enough now that tests will make it look much more professional.


give me readme update

Replace your current README.md with this updated Version 17 README.

# Encoded Command Analyzer

![Python](https://img.shields.io/badge/Python-3.x-blue)
![License: MIT](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)
![Project Type](https://img.shields.io/badge/Project-Detection%20Engineering-red)
![Interface](https://img.shields.io/badge/Interface-CLI%20%7C%20GUI-purple)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-orange)
![Exports](https://img.shields.io/badge/Exports-JSON%20%7C%20CSV%20%7C%20Markdown-yellow)
![Decoding](https://img.shields.io/badge/Decoding-Base64%20%7C%20URL%20%7C%20Hex%20%7C%20XOR-blueviolet)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)

## Overview

**Encoded Command Analyzer** is a Python-based detection engineering utility for decoding and analyzing encoded command-line content.

The tool is designed to help security analysts and detection engineers triage suspicious commands, identify signs of PowerShell abuse, detect common obfuscation patterns, map findings to MITRE ATT&CK techniques, and produce analyst-friendly output for investigations.

This project started as a simple Base64 decoder and has expanded into a lightweight encoded command analysis tool with CLI support, GUI support, batch file analysis, chained decoding, compressed Base64 support, XOR Hex decoding, suspicious keyword detection, risk scoring, MITRE ATT&CK mapping, and analyst-ready exports.

---

## Current Version

**Version 17**

### Current Capabilities

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
- Assign a risk level based on detected indicators
- Explain why a command may be suspicious
- Map suspicious indicators to MITRE ATT&CK techniques
- Export analysis results to JSON
- Export analysis results to CSV
- Export analyst triage reports to Markdown
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
- Compressed payload delivery
- Chained encoding and obfuscation
- Lightweight XOR-obfuscated strings

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
| Gzip Base64 | Supported |
| Deflate Base64 | Supported |
| Raw Deflate Base64 | Supported |
| XOR Hex | Supported |

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

## XOR Hex Decoding

Version 17 adds single-byte XOR Hex decoding support.

The tool can brute-force possible XOR keys, score the decoded candidates, and return the highest-confidence result.

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
```

XOR Hex detection is confidence-based and intended to help analysts identify suspicious strings during triage.

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
- Export results to JSON, CSV, and Markdown
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

### Analyze XOR Hex Input

```powershell
python base64_decoder.py --input "534c544651504b464f4f0d465b46030e464d40036a667b"
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
│   ├── analysis_result.csv
│   └── triage_report.md
├── README.md
├── LICENSE
└── .gitignore
```

### File Purpose

| File | Purpose |
|---|---|
| `base64_decoder.py` | CLI entry point and command-line argument handler |
| `encoded_command_gui.py` | Tkinter GUI entry point |
| `decoder_engine.py` | Decoding logic for Base64, UTF-16LE, URL, Hex, chained decoding, compressed Base64, and XOR Hex |
| `detection_engine.py` | Suspicious keyword detection, risk scoring, analysis logic, and MITRE ATT&CK mapping |
| `report_exporter.py` | JSON, CSV, and Markdown export functions |
| `samples/` | Sample input files for testing |
| `output/` | Stores exported analysis results and triage reports |

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

## Analyst Triage Report

The generated Markdown triage report includes:

- Summary
- Total results
- Highest risk level
- Highest score
- Original input
- Decoded output
- Suspicious keyword matches
- Risk score
- Risk reasons
- MITRE ATT&CK mappings

The report is saved to:

```text
output/triage_report.md
```

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
9. Export results to JSON, CSV, or Markdown.
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

- Version 18: Add unit tests
- Version 19: Package as an executable
- Version 20: Add detection rule mapping
- Version 21: Add configurable keyword rules
- Version 22: Add HTML report export
- Version 23: Add enrichment fields for analyst notes

---

## Disclaimer

This tool is intended for defensive security, detection engineering, malware analysis support, and security training purposes only.

Decoded content should always be reviewed carefully in a controlled environment.

---

## License

This project is licensed under the MIT License.
Then commit it:

git status
git add README.md
git commit -m "Update README for XOR hex decoding support"
git push

next

Thought for a few seconds
Next is Version 18: Add Unit Tests.

This is a big portfolio upgrade because it shows you can validate your detection logic, not just write scripts.

Version 18 goal
Add a tests/ folder and verify that your decoder correctly handles:

Base64
PowerShell UTF-16LE
URL encoding
Hex encoding
Chained encoding
Gzip Base64
XOR Hex
Risk scoring
MITRE mapping
We’ll use Python’s built-in unittest, so no extra packages are needed.

Step 1: Create a tests folder
Inside:

C:\encoded_command_analyzer
Create:

tests
Then inside tests, create:

test_decoder_engine.py
Step 2: Add tests for decoder_engine.py
Paste this into:

tests\test_decoder_engine.py
import base64
import gzip
import unittest

from decoder_engine import decode_input


class TestDecoderEngine(unittest.TestCase):

    def test_utf8_base64_decode(self):
        results = decode_input("SGVsbG8gd29ybGQ=")

        decoded_values = [result["decoded_text"] for result in results]

        self.assertIn("Hello world", decoded_values)

    def test_powershell_utf16le_decode(self):
        results = decode_input("cABvAHcAZQByAHMAaABlAGwAbAAuAGUAeABlACAALQBlAG4AYwAgAEkARQBYAA==")

        decoded_values = [result["decoded_text"] for result in results]

        self.assertIn("powershell.exe -enc IEX", decoded_values)

    def test_url_decode(self):
        results = decode_input("powershell%2Eexe%20-enc%20IEX")

        decoded_values = [result["decoded_text"] for result in results]

        self.assertIn("powershell.exe -enc IEX", decoded_values)

    def test_hex_decode(self):
        results = decode_input("706f7765727368656c6c2e657865202d656e6320494558")

        decoded_values = [result["decoded_text"] for result in results]

        self.assertIn("powershell.exe -enc IEX", decoded_values)

    def test_chained_base64_url_decode(self):
        results = decode_input("cG93ZXJzaGVsbCUyRWV4ZSUyMC1lbmMlMjBJRVg=")

        decoded_values = [result["decoded_text"] for result in results]

        self.assertIn("powershell%2Eexe%20-enc%20IEX", decoded_values)
        self.assertIn("powershell.exe -enc IEX", decoded_values)

    def test_gzip_base64_decode(self):
        test_text = "powershell.exe -enc IEX"

        compressed = gzip.compress(test_text.encode("utf-8"))
        encoded = base64.b64encode(compressed).decode("utf-8")

        results = decode_input(encoded)

        decoded_values = [result["decoded_text"] for result in results]

        self.assertIn(test_text, decoded_values)

    def test_xor_hex_decode(self):
        results = decode_input("534c544651504b464f4f0d465b46030e464d40036a667b")

        decoded_values = [result["decoded_text"] for result in results]

        self.assertIn("powershell.exe -enc IEX", decoded_values)


if __name__ == "__main__":
    unittest.main()
Step 3: Create test for detection_engine.py
Create another file:

tests\test_detection_engine.py
Paste this:

import unittest

from detection_engine import (
    analyze_decoded_result,
    calculate_risk_score,
    check_suspicious_keywords,
    map_mitre_attack
)


class TestDetectionEngine(unittest.TestCase):

    def test_suspicious_keyword_detection(self):
        decoded_text = "powershell.exe -enc IEX"

        keywords = check_suspicious_keywords(decoded_text)

        self.assertIn("powershell", keywords)
        self.assertIn("-enc", keywords)
        self.assertIn("iex", keywords)

    def test_risk_score_high(self):
        found_keywords = ["powershell", "-enc", "iex"]

        risk_level, score, reasons = calculate_risk_score(found_keywords)

        self.assertEqual(risk_level, "High")
        self.assertEqual(score, 7)
        self.assertGreater(len(reasons), 0)

    def test_mitre_mapping(self):
        found_keywords = ["powershell", "-enc", "iex"]

        mappings = map_mitre_attack(found_keywords)

        technique_ids = [mapping["technique_id"] for mapping in mappings]

        self.assertIn("T1059.001", technique_ids)
        self.assertIn("T1027", technique_ids)

    def test_full_analysis_result(self):
        result = {
            "encoding": "UTF-8",
            "decode_level": 1,
            "decoded_text": "powershell.exe -enc IEX"
        }

        analysis = analyze_decoded_result(result)

        self.assertEqual(analysis["risk_level"], "High")
        self.assertEqual(analysis["risk_score"], 7)
        self.assertIn("mitre_attack", analysis)
        self.assertGreater(len(analysis["mitre_attack"]), 0)


if __name__ == "__main__":
    unittest.main()
Step 4: Run all tests
From your project folder:

cd C:\encoded_command_analyzer
python -m unittest discover -s tests
Expected result:

Ran 11 tests in ...

OK
Step 5: If import errors happen
If you get something like:

ModuleNotFoundError: No module named 'decoder_engine'
Run it this way from the project root:

python -m unittest discover -s tests -p "test_*.py"
If it still happens, create an empty file inside tests named:

__init__.py
Then try again.

Step 6: Commit Version 18
Once tests pass:

git status
git add .
git commit -m "Add unit tests for decoder and detection engines"
git push
After this, update the README with a Testing section.


next

Thought for a couple of seconds
Next step should be update the README for Version 18 unit tests before moving to packaging.

Add these sections to your README.

Update Current Version
Change:

**Version 17**
to:

**Version 18**
Add Unit Testing to Current Capabilities
Under Current Capabilities, add:

- Unit tests for decoder logic
- Unit tests for detection logic
- Unit tests for risk scoring
- Unit tests for MITRE ATT&CK mapping
Add Testing Section
Paste this section somewhere after Requirements or before Usage:

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
Expected result:

OK
Test files are located in:

tests/
├── test_decoder_engine.py
└── test_detection_engine.py

## Update Project Structure

Change your structure section to include `tests/`:

```markdown
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
├── tests/
│   ├── test_decoder_engine.py
│   └── test_detection_engine.py
├── output/
│   ├── analysis_result.json
│   ├── analysis_result.csv
│   └── triage_report.md
├── README.md
├── LICENSE
└── .gitignore

## Update File Purpose Table

Add this row:

```markdown
| `tests/` | Unit tests for decoder and detection logic |
Update Roadmap
Change the roadmap from this:

- Version 18: Add unit tests
- Version 19: Package as an executable
to this:

- Version 19: Package as an executable
- Version 20: Add detection rule mapping
- Version 21: Add configurable keyword rules
- Version 22: Add HTML report export
- Version 23: Add enrichment fields for analyst notes
Commit README update
Run:

git status
git add README.md
git commit -m "Update README for unit testing support"
git push
After that, the next real code phase is Version 19: package the GUI as a Windows executable with PyInstaller.


rewrite readme for me

Thought for a couple of seconds
Absolutely — replace your entire README.md with this updated Version 18 README:

# Encoded Command Analyzer

![Python](https://img.shields.io/badge/Python-3.x-blue)
![License: MIT](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)
![Project Type](https://img.shields.io/badge/Project-Detection%20Engineering-red)
![Interface](https://img.shields.io/badge/Interface-CLI%20%7C%20GUI-purple)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-orange)
![Exports](https://img.shields.io/badge/Exports-JSON%20%7C%20CSV%20%7C%20Markdown-yellow)
![Decoding](https://img.shields.io/badge/Decoding-Base64%20%7C%20URL%20%7C%20Hex%20%7C%20XOR-blueviolet)
![Testing](https://img.shields.io/badge/Testing-Unittest-brightgreen)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)

## Overview

**Encoded Command Analyzer** is a Python-based detection engineering utility for decoding and analyzing encoded command-line content.

The tool is designed to help security analysts and detection engineers triage suspicious commands, identify signs of PowerShell abuse, detect common obfuscation patterns, map findings to MITRE ATT&CK techniques, and produce analyst-friendly output for investigations.

This project started as a simple Base64 decoder and has expanded into a lightweight encoded command analysis tool with CLI support, GUI support, batch file analysis, chained decoding, compressed Base64 support, XOR Hex decoding, suspicious keyword detection, risk scoring, MITRE ATT&CK mapping, analyst-ready exports, and unit testing.

---

## Current Version

**Version 18**

### Current Capabilities

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
- Assign a risk level based on detected indicators
- Explain why a command may be suspicious
- Map suspicious indicators to MITRE ATT&CK techniques
- Export analysis results to JSON
- Export analysis results to CSV
- Export analyst triage reports to Markdown
- Provide both CLI and Tkinter GUI interfaces
- Display a GUI risk banner for quick analyst review
- Unit tests for decoder logic
- Unit tests for detection logic
- Unit tests for risk scoring
- Unit tests for MITRE ATT&CK mapping

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
| Gzip Base64 | Supported |
| Deflate Base64 | Supported |
| Raw Deflate Base64 | Supported |
| XOR Hex | Supported |

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

## XOR Hex Decoding

Version 17 added single-byte XOR Hex decoding support.

The tool can brute-force possible XOR keys, score decoded candidates, and return the highest-confidence result.

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
```

XOR Hex detection is confidence-based and intended to help analysts identify suspicious strings during triage.

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
- Export results to JSON, CSV, and Markdown
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
├── tests/
│   ├── test_decoder_engine.py
│   └── test_detection_engine.py
├── output/
│   ├── analysis_result.json
│   ├── analysis_result.csv
│   └── triage_report.md
├── README.md
├── LICENSE
└── .gitignore
```

### File Purpose

| File | Purpose |
|---|---|
| `base64_decoder.py` | CLI entry point and command-line argument handler |
| `encoded_command_gui.py` | Tkinter GUI entry point |
| `decoder_engine.py` | Decoding logic for Base64, UTF-16LE, URL, Hex, chained decoding, compressed Base64, and XOR Hex |
| `detection_engine.py` | Suspicious keyword detection, risk scoring, analysis logic, and MITRE ATT&CK mapping |
| `report_exporter.py` | JSON, CSV, and Markdown export functions |
| `samples/` | Sample input files for testing |
| `tests/` | Unit tests for decoder and detection logic |
| `output/` | Stores exported analysis results and triage reports |

---

## Requirements

This project currently uses Python standard libraries only.

No external packages are required.

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

## Analyst Triage Report

The generated Markdown triage report includes:

- Summary
- Total results
- Highest risk level
- Highest score
- Original input
- Decoded output
- Suspicious keyword matches
- Risk score
- Risk reasons
- MITRE ATT&CK mappings

The report is saved to:

```text
output/triage_report.md
```

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
9. Export results to JSON, CSV, or Markdown.
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

- Version 19: Package as an executable
- Version 20: Add detection rule mapping
- Version 21: Add configurable keyword rules
- Version 22: Add HTML report export
- Version 23: Add enrichment fields for analyst notes

---

## Disclaimer

This tool is intended for defensive security, detection engineering, malware analysis support, and security training purposes only.

Decoded content should always be reviewed carefully in a controlled environment.

---

## License

This project is licensed under the MIT License.
Then commit it:

git status
git add README.md
git commit -m "Update README for unit testing support"
git push

next

Thought for a couple of seconds
Next is Version 19: Package the GUI as a Windows executable.

This lets you run the tool as an .exe without typing:

python encoded_command_gui.py
We’ll use PyInstaller.

Step 1: Install PyInstaller
From your project folder:

cd C:\encoded_command_analyzer
pip install pyinstaller
Verify it installed:

pyinstaller --version
Step 2: Build the GUI executable
Run this:

pyinstaller --onefile --windowed --name EncodedCommandAnalyzer encoded_command_gui.py
What the options mean:

--onefile     Builds one EXE file
--windowed    Prevents a console window from opening behind the GUI
--name        Sets the EXE name
Step 3: Find the EXE
After it finishes, check:

C:\encoded_command_analyzer\dist\EncodedCommandAnalyzer.exe
Run it:

.\dist\EncodedCommandAnalyzer.exe
The GUI should open.

Step 4: Test the EXE
Test with:

cG93ZXJzaGVsbCUyRWV4ZSUyMC1lbmMlMjBJRVg=
Expected:

powershell.exe -enc IEX
Risk Level: High
MITRE ATT&CK Mapping
Then test batch mode from the GUI by loading:

samples\sample_batch.txt
Step 5: Update .gitignore
Open .gitignore and make sure these are included:

build/
dist/
*.spec
__pycache__/
*.pyc
output/
Important: I would not commit the dist/ or build/ folders to GitHub. They can get large and messy. Commit only the source code and README updates.

Step 6: Optional: Keep the .spec file?
For now, ignore it using:

*.spec
Later, if you customize icons or advanced packaging, you can track the .spec file. For now, keep it simple.

Step 7: Commit the packaging support
Since the EXE itself should not be committed, this commit will mostly be .gitignore and README updates if you add them.

Run:

git status
If you see dist/, build/, or .spec, make sure they are ignored.

Then:

git add .gitignore
git commit -m "Add packaging ignore rules"
git push
Step 8: Add a release manually on GitHub
If you want to share the .exe, use GitHub Releases instead of committing it into the repo:

Go to your GitHub repo

Click Releases

Click Draft a new release

Tag it like:

v19.0
Title:

Encoded Command Analyzer v19
Upload:

dist\EncodedCommandAnalyzer.exe
This is the better way to distribute the executable.

Next after this should be Version 20: Detection rule mapping, where decoded findings can suggest related Sigma/Sentinel-style detection ideas.


====================================
Timestamp: 2026-05-19T17:46:32
Detected Encoding: UTF-8
Decode Level: 1

Decoded Output:
------------------------------------
powershell%2Eexe%20-enc%20IEX

Suspicious Keyword Check:
------------------------------------
- powershell
- -enc
- iex

Risk Score:
------------------------------------
Risk Level: High
Score: 7

Reasons:
- powershell may indicate suspicious command-line or PowerShell behavior.
- -enc may indicate suspicious command-line or PowerShell behavior.
- iex is commonly used in malicious or obfuscated script execution.

MITRE ATT&CK Mapping:
------------------------------------
- T1059.001 - PowerShell (Execution)
  Reason: PowerShell is commonly used for command and script execution.
- T1027 - Obfuscated Files or Information (Defense Evasion)
  Reason: Encoded command usage may indicate command obfuscation.

====================================
Timestamp: 2026-05-19T17:46:32
Detected Encoding: URL
Decode Level: 2
Source Encoding: UTF-8

Decoded Output:
------------------------------------
powershell.exe -enc IEX

Suspicious Keyword Check:
------------------------------------
- powershell
- -enc
- iex

Risk Score:
------------------------------------
Risk Level: High
Score: 7

Reasons:
- powershell may indicate suspicious command-line or PowerShell behavior.
- -enc may indicate suspicious command-line or PowerShell behavior.
- iex is commonly used in malicious or obfuscated script execution.

MITRE ATT&CK Mapping:
------------------------------------
- T1059.001 - PowerShell (Execution)
  Reason: PowerShell is commonly used for command and script execution.
- T1027 - Obfuscated Files or Information (Defense Evasion)
  Reason: Encoded command usage may indicate command obfuscation.

That output looks good. Your packaged GUI/EXE is still running the chained decode correctly:

Base64 UTF-8 → URL decode → powershell.exe -enc IEX
It also kept the important detection engineering pieces:

Risk Level: High
MITRE ATT&CK:
T1059.001 - PowerShell
T1027 - Obfuscated Files or Information
So Version 19 is working.

Now do the cleanup/commit step:

git status
Make sure you do not commit these if they show up:

build/
dist/
EncodedCommandAnalyzer.spec
Your .gitignore should include:

build/
dist/
*.spec
__pycache__/
*.pyc
output/
Then commit the packaging support:

git add .gitignore README.md
git commit -m "Add packaging support for Windows executable"
git push
If you did not change the README yet, only commit .gitignore:

git add .gitignore
git commit -m "Add packaging ignore rules"
git push
Next step after this is updating the README for Version 19 with a short Windows EXE Packaging section.



.gitignore
File
where do i add it

Thought for a second
Add those lines at the bottom of your .gitignore file.

Open this file in VS Code:

C:\encoded_command_analyzer\.gitignore
Scroll to the bottom and add:

# PyInstaller build artifacts
build/
dist/
*.spec

# Python cache
__pycache__/
*.pyc

# Analyzer output files
output/
So your .gitignore can have existing Python rules at the top, and these extra project rules at the bottom.

Then save it and run:

git status
If build/, dist/, or EncodedCommandAnalyzer.spec still show up, run:

git rm -r --cached build dist
git rm --cached EncodedCommandAnalyzer.spec
Only use those commands if Git already started tracking them.

Then commit:

git add .gitignore
git commit -m "Add packaging ignore rules"
git push

next

Thought for a second
Next, update the README for Version 19 packaging support.

Add these updates to your README.

1. Change Current Version
Find:

**Version 18**
Change to:

**Version 19**
2. Add this under Current Capabilities
Add these bullets:

- Package the Tkinter GUI as a Windows executable
- Run the GUI without launching Python manually
- Distribute the executable through GitHub Releases
3. Add this new section before Roadmap
---

## Windows Executable Packaging

Version 19 adds support for packaging the Tkinter GUI as a Windows executable using PyInstaller.

Install PyInstaller:

```powershell
pip install pyinstaller
Build the executable:

pyinstaller --onefile --windowed --name EncodedCommandAnalyzer encoded_command_gui.py
The executable will be created here:

dist/EncodedCommandAnalyzer.exe
Run the executable:

.\dist\EncodedCommandAnalyzer.exe
Packaging Notes
The following PyInstaller build artifacts are ignored by Git:

build/
dist/
*.spec
The executable should not be committed directly to the repository. Use GitHub Releases to distribute packaged builds.


## 4. Update Project Structure

Keep `build/` and `dist/` **out** of the structure because they are ignored. You can add a note under Project Structure:

```markdown
Build artifacts such as `build/`, `dist/`, and `*.spec` are intentionally excluded from source control.
5. Update Roadmap
Change:

- Version 19: Package as an executable
- Version 20: Add detection rule mapping
to:

- Version 20: Add detection rule mapping
- Version 21: Add configurable keyword rules
- Version 22: Add HTML report export
- Version 23: Add enrichment fields for analyst notes
Then commit:

git status
git add README.md
git commit -m "Update README for Windows executable packaging"
git push
After that, Version 20 should be detection rule mapping, where the tool suggests related detection ideas based on the decoded findings.


rewrite the whole readme in markdown

Thought for 4s
Replace your entire README.md with this Version 19 README:

# Encoded Command Analyzer

![Python](https://img.shields.io/badge/Python-3.x-blue)
![License: MIT](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)
![Project Type](https://img.shields.io/badge/Project-Detection%20Engineering-red)
![Interface](https://img.shields.io/badge/Interface-CLI%20%7C%20GUI-purple)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-orange)
![Exports](https://img.shields.io/badge/Exports-JSON%20%7C%20CSV%20%7C%20Markdown-yellow)
![Decoding](https://img.shields.io/badge/Decoding-Base64%20%7C%20URL%20%7C%20Hex%20%7C%20XOR-blueviolet)
![Testing](https://img.shields.io/badge/Testing-Unittest-brightgreen)
![Packaging](https://img.shields.io/badge/Packaging-PyInstaller-lightgrey)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)

## Overview

**Encoded Command Analyzer** is a Python-based detection engineering utility for decoding and analyzing encoded command-line content.

The tool is designed to help security analysts and detection engineers triage suspicious commands, identify signs of PowerShell abuse, detect common obfuscation patterns, map findings to MITRE ATT&CK techniques, and produce analyst-friendly output for investigations.

This project started as a simple Base64 decoder and has expanded into a lightweight encoded command analysis tool with CLI support, GUI support, batch file analysis, chained decoding, compressed Base64 support, XOR Hex decoding, suspicious keyword detection, risk scoring, MITRE ATT&CK mapping, analyst-ready exports, unit testing, and Windows executable packaging.

---

## Current Version

**Version 19**

### Current Capabilities

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
- Assign a risk level based on detected indicators
- Explain why a command may be suspicious
- Map suspicious indicators to MITRE ATT&CK techniques
- Export analysis results to JSON
- Export analysis results to CSV
- Export analyst triage reports to Markdown
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
| Gzip Base64 | Supported |
| Deflate Base64 | Supported |
| Raw Deflate Base64 | Supported |
| XOR Hex | Supported |

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
```

XOR Hex detection is confidence-based and intended to help analysts identify suspicious strings during triage.

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
- Export results to JSON, CSV, and Markdown
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
├── tests/
│   ├── test_decoder_engine.py
│   └── test_detection_engine.py
├── output/
│   ├── analysis_result.json
│   ├── analysis_result.csv
│   └── triage_report.md
├── README.md
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
| `detection_engine.py` | Suspicious keyword detection, risk scoring, analysis logic, and MITRE ATT&CK mapping |
| `report_exporter.py` | JSON, CSV, and Markdown export functions |
| `samples/` | Sample input files for testing |
| `tests/` | Unit tests for decoder and detection logic |
| `output/` | Stores exported analysis results and triage reports |

---

## Requirements

This project currently uses Python standard libraries only.

No external packages are required for the analyzer itself.

Tested with:

```text
Python 3.x
```

For Windows executable packaging, PyInstaller is required:

```powershell
pip install pyinstaller
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

Version 19 adds support for packaging the Tkinter GUI as a Windows executable using PyInstaller.

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

## Analyst Triage Report

The generated Markdown triage report includes:

- Summary
- Total results
- Highest risk level
- Highest score
- Original input
- Decoded output
- Suspicious keyword matches
- Risk score
- Risk reasons
- MITRE ATT&CK mappings

The report is saved to:

```text
output/triage_report.md
```

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
9. Export results to JSON, CSV, or Markdown.
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

- Version 20: Add detection rule mapping
- Version 21: Add configurable keyword rules
- Version 22: Add HTML report export
- Version 23: Add enrichment fields for analyst notes

---

## Disclaimer

This tool is intended for defensive security, detection engineering, malware analysis support, and security training purposes only.

Decoded content should always be reviewed carefully in a controlled environment.

---

## License

This project is licensed under the MIT License.
Then commit it:

git status
git add README.md
git commit -m "Update README for Windows executable packaging"
git push

should i make this a release?

Thought for a couple of seconds
Yes — I would make this a GitHub Release, especially since you just packaged it as an .exe.

Do not commit the .exe into the repo. Use a release so your source code stays clean, and the executable is available as a downloadable asset.

Use this release style:

Tag: v0.19.0
Release title: Encoded Command Analyzer v0.19.0
Why v0.19.0 instead of v19.0?

Because this is still an evolving project. v0.19.0 communicates:

0 = pre-1.0 project / still growing
19 = your current feature version
0 = patch number
For the release notes, you can paste this:

# Encoded Command Analyzer v0.19.0

This release adds Windows executable packaging support for the Encoded Command Analyzer GUI.

## Highlights

- Packaged the Tkinter GUI as a Windows executable using PyInstaller
- Added support for running the analyzer without launching Python manually
- Maintained support for CLI and GUI workflows
- Includes decoding support for:
  - Base64 UTF-8
  - PowerShell UTF-16LE EncodedCommand
  - URL encoding
  - Hex encoding
  - Chained encoding
  - Gzip/Deflate Base64
  - XOR Hex
- Includes suspicious keyword detection
- Includes risk scoring
- Includes MITRE ATT&CK mapping
- Includes JSON, CSV, and Markdown triage report exports
- Includes unit tests for decoder and detection logic

## Download

Download `EncodedCommandAnalyzer.exe` from the release assets.

## Notes

This tool is intended for defensive security, detection engineering, malware analysis support, and analyst training.

Decoded content should always be reviewed carefully in a controlled environment.
On GitHub:

Go to your repo.

Click Releases.

Click Draft a new release.

Create a new tag:

v0.19.0
Title it:

Encoded Command Analyzer v0.19.0
Upload:

dist\EncodedCommandAnalyzer.exe
Paste the release notes.

Click Publish release.

After that, your GitHub project will look much more professional because it has source code, documentation, tests, and a downloadable release.


why is this not v1 but v0.x

Because v0.x usually means “pre-1.0”: the project works, but the public interface, structure, features, and behavior may still change.

For your tool, that makes sense because you are still actively adding major features:

Version 20: detection rule mapping
Version 21: configurable keyword rules
Version 22: HTML report export
Version 23: analyst note fields
So v0.19.0 basically says:

This is a working release, but the project is still evolving before a stable 1.0.

A v1.0.0 release usually means:

The core feature set is stable
The CLI arguments are unlikely to change
The file structure is mostly settled
The documentation is complete enough
The tool has been tested enough
The release is something you would confidently present as the first stable version
That said, you can absolutely call it v1.0.0 if you want this to be your first official portfolio release.

For your situation, I would use one of these:

v0.19.0 = technically correct, still actively building
v1.0.0-beta = good portfolio-friendly middle ground
v1.0.0 = first stable public release
My recommendation:

Use v1.0.0-beta
Why? It looks better than v0.19.0 for GitHub, but still gives you room to improve it without claiming it is fully final.

Release title:

Encoded Command Analyzer v1.0.0-beta
Tag:

v1.0.0-beta
Then later, once you add detection rule mapping and configurable rules, make that:

v1.0.0

next

Thought for a second
Next step should be Version 20: Detection Rule Mapping.

This will make the tool more detection-engineering focused by suggesting related detection ideas based on what the decoded command contains.

For example, if the decoded output contains:

powershell.exe -enc IEX
The tool could add a new section like:

Detection Rule Mapping:
- Suspicious PowerShell EncodedCommand Execution
- PowerShell Invoke-Expression Usage
- PowerShell Obfuscation or Encoded Payload
This is different from MITRE mapping. MITRE tells you the technique. Detection mapping tells you what kind of rule or alert could detect it.

Version 20 goal
Add a new field to every analysis result:

"detection_rules": [...]
Each rule suggestion will include:

Rule name
Description
Suggested severity
Related keywords
Possible log sources
Example output:

Detection Rule Mapping:
------------------------------------
- Suspicious PowerShell EncodedCommand Execution
  Severity: High
  Log Sources: DeviceProcessEvents, Sysmon Event ID 1, Security Event ID 4688
  Reason: Detected PowerShell with encoded command indicators.

- PowerShell Invoke-Expression Usage
  Severity: Medium
  Log Sources: DeviceProcessEvents, PowerShell Script Block Logs
  Reason: Detected IEX or Invoke-Expression usage.
Step 1: Open detection_engine.py
Add this function under your map_mitre_attack() function:

def map_detection_rules(found_keywords):
    detection_rules = []

    keyword_set = set(found_keywords)

    rule_definitions = [
        {
            "rule_name": "Suspicious PowerShell EncodedCommand Execution",
            "description": "Detects PowerShell execution using encoded command indicators.",
            "severity": "High",
            "required_keywords": ["powershell", "-enc"],
            "log_sources": [
                "Microsoft Defender DeviceProcessEvents",
                "Sysmon Event ID 1",
                "Windows Security Event ID 4688"
            ],
            "reason": "PowerShell execution with encoded command usage may indicate obfuscated script execution."
        },
        {
            "rule_name": "PowerShell Invoke-Expression Usage",
            "description": "Detects use of IEX or Invoke-Expression patterns.",
            "severity": "Medium",
            "required_keywords": ["iex"],
            "log_sources": [
                "Microsoft Defender DeviceProcessEvents",
                "PowerShell Script Block Logs",
                "Sysmon Event ID 1"
            ],
            "reason": "IEX is commonly used to execute PowerShell content in memory."
        },
        {
            "rule_name": "PowerShell Remote Download Cradle",
            "description": "Detects PowerShell download cradle behavior using WebClient or DownloadString.",
            "severity": "High",
            "required_keywords": ["downloadstring"],
            "log_sources": [
                "PowerShell Script Block Logs",
                "Microsoft Defender DeviceProcessEvents",
                "Proxy or Web Gateway Logs"
            ],
            "reason": "DownloadString may indicate remote payload retrieval."
        },
        {
            "rule_name": "Base64 Decoding Inside Script Content",
            "description": "Detects use of FromBase64String inside decoded script content.",
            "severity": "Medium",
            "required_keywords": ["frombase64string"],
            "log_sources": [
                "PowerShell Script Block Logs",
                "Microsoft Defender DeviceProcessEvents"
            ],
            "reason": "FromBase64String may indicate embedded encoded payload content."
        },
        {
            "rule_name": "Hidden PowerShell Window Execution",
            "description": "Detects PowerShell or script execution using hidden window indicators.",
            "severity": "Medium",
            "required_keywords": ["hidden"],
            "log_sources": [
                "Microsoft Defender DeviceProcessEvents",
                "Sysmon Event ID 1",
                "Windows Security Event ID 4688"
            ],
            "reason": "Hidden window execution may indicate an attempt to conceal activity from the user."
        },
        {
            "rule_name": "Windows Script Host Execution",
            "description": "Detects suspicious Windows Script Host usage.",
            "severity": "Medium",
            "required_keywords": ["wscript"],
            "log_sources": [
                "Microsoft Defender DeviceProcessEvents",
                "Sysmon Event ID 1",
                "Windows Security Event ID 4688"
            ],
            "reason": "wscript may be used to execute script content on Windows endpoints."
        },
        {
            "rule_name": "Command Shell Execution",
            "description": "Detects command shell usage that may support script execution or payload staging.",
            "severity": "Low",
            "required_keywords": ["cmd.exe"],
            "log_sources": [
                "Microsoft Defender DeviceProcessEvents",
                "Sysmon Event ID 1",
                "Windows Security Event ID 4688"
            ],
            "reason": "cmd.exe usage may provide useful context for process-chain investigation."
        }
    ]

    for rule in rule_definitions:
        required_keywords = set(rule["required_keywords"])

        if required_keywords.issubset(keyword_set):
            detection_rules.append(rule)

    return detection_rules
Step 2: Update analyze_decoded_result()
In the same file, find:

mitre_mappings = map_mitre_attack(found_keywords)
Add this right under it:

detection_rules = map_detection_rules(found_keywords)
Then inside the analysis = { ... } dictionary, add:

"detection_rules": detection_rules
Your updated section should look like this:

def analyze_decoded_result(result):
    decoded_text = result["decoded_text"]
    found_keywords = check_suspicious_keywords(decoded_text)
    risk_level, score, reasons = calculate_risk_score(found_keywords)
    mitre_mappings = map_mitre_attack(found_keywords)
    detection_rules = map_detection_rules(found_keywords)

    analysis = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "encoding": result["encoding"],
        "decoded_text": decoded_text,
        "suspicious_keywords": found_keywords,
        "risk_level": risk_level,
        "risk_score": score,
        "reasons": reasons,
        "mitre_attack": mitre_mappings,
        "detection_rules": detection_rules
    }

    if "decode_level" in result:
        analysis["decode_level"] = result["decode_level"]

    if "source_encoding" in result:
        analysis["source_encoding"] = result["source_encoding"]

    return analysis
Step 3: Test quickly in CLI
Before updating GUI/export formatting, run:

python base64_decoder.py --input "cG93ZXJzaGVsbCUyRWV4ZSUyMC1lbmMlMjBJRVg=" --export
The console will not show the detection rules yet, but the JSON should include them.

Open:

notepad output\analysis_result.json
Search for:

detection_rules
You should see rule suggestions in the JSON.

Once that works, the next step is updating the CLI, GUI, CSV, and Markdown report so detection rule mappings display cleanly.


PS C:\encoded_command_analyzer> python base64_decoder.py --input "cG93ZXJzaGVsbCUyRWV4ZSUyMC1lbmMlMjBJRVg=" --export
Traceback (most recent call last):
  File "C:\encoded_command_analyzer\base64_decoder.py", line 6, in <module>
    from detection_engine import analyze_decoded_result
  File "C:\encoded_command_analyzer\detection_engine.py", line 311
    "detection_rules": detection_rules
    ^^^^^^^^^^^^^^^^^
SyntaxError: invalid syntax
PS C:\encoded_command_analyzer>

Thought for a second
That error means the line before this is missing a comma inside your dictionary:

"detection_rules": detection_rules
In Python dictionaries, every item needs a comma except the last one.

Your broken section probably looks like this:

"mitre_attack": mitre_mappings
"detection_rules": detection_rules
It needs to be:

"mitre_attack": mitre_mappings,
"detection_rules": detection_rules
Fix detection_engine.py
Open:

C:\encoded_command_analyzer\detection_engine.py
Find your analyze_decoded_result() function and replace the whole function with this clean version:

def analyze_decoded_result(result):
    decoded_text = result["decoded_text"]
    found_keywords = check_suspicious_keywords(decoded_text)
    risk_level, score, reasons = calculate_risk_score(found_keywords)
    mitre_mappings = map_mitre_attack(found_keywords)
    detection_rules = map_detection_rules(found_keywords)

    analysis = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "encoding": result["encoding"],
        "decoded_text": decoded_text,
        "suspicious_keywords": found_keywords,
        "risk_level": risk_level,
        "risk_score": score,
        "reasons": reasons,
        "mitre_attack": mitre_mappings,
        "detection_rules": detection_rules
    }

    if "decode_level" in result:
        analysis["decode_level"] = result["decode_level"]

    if "source_encoding" in result:
        analysis["source_encoding"] = result["source_encoding"]

    return analysis
The key fix is this comma:

"mitre_attack": mitre_mappings,
Then run it again:

python base64_decoder.py --input "cG93ZXJzaGVsbCUyRWV4ZSUyMC1lbmMlMjBJRVg=" --export
If it works, open the JSON:

notepad output\analysis_result.json
Search for:

detection_rules

PS C:\encoded_command_analyzer> python base64_decoder.py --input "cG93ZXJzaGVsbCUyRWV4ZSUyMC1lbmMlMjBJRVg=" --export
====================================
Timestamp: 2026-05-19T17:57:06
Detected Encoding: UTF-8
Decode Level: 1

Decoded Output:
------------------------------------
powershell%2Eexe%20-enc%20IEX

Suspicious Keyword Check:
------------------------------------
- powershell
- -enc
- iex

Risk Score:
------------------------------------
Risk Level: High
Score: 7

Reasons:
- powershell may indicate suspicious command-line or PowerShell behavior.
- -enc may indicate suspicious command-line or PowerShell behavior.
- iex is commonly used in malicious or obfuscated script execution.

MITRE ATT&CK Mapping:
------------------------------------
- T1059.001 - PowerShell (Execution)
  Reason: PowerShell is commonly used for command and script execution.
- T1027 - Obfuscated Files or Information (Defense Evasion)
  Reason: Encoded command usage may indicate command obfuscation.

====================================
Timestamp: 2026-05-19T17:57:06
Detected Encoding: URL
Decode Level: 2
Source Encoding: UTF-8

Decoded Output:
------------------------------------
powershell.exe -enc IEX

Suspicious Keyword Check:
------------------------------------
- powershell
- -enc
- iex

Risk Score:
------------------------------------
Risk Level: High
Score: 7

Reasons:
- powershell may indicate suspicious command-line or PowerShell behavior.
- -enc may indicate suspicious command-line or PowerShell behavior.
- iex is commonly used in malicious or obfuscated script execution.

MITRE ATT&CK Mapping:
------------------------------------
- T1059.001 - PowerShell (Execution)
  Reason: PowerShell is commonly used for command and script execution.
- T1027 - Obfuscated Files or Information (Defense Evasion)
  Reason: Encoded command usage may indicate command obfuscation.

====================================
Analysis Summary
====================================
Total Results: 2
Highest Risk: High
Highest Score: 7
====================================

Export Complete:
- JSON:     output/analysis_result.json
- CSV:      output/analysis_result.csv
- Markdown: output/triage_report.md
PS C:\encoded_command_analyzer>

Good — the backend is working now and exports are being created.

Next we need to display the detection rule mappings in the CLI, GUI, CSV, and Markdown report. Right now they should be in the JSON, but not showing in the console output yet.

Step 1: Update CLI output in base64_decoder.py
Open:

C:\encoded_command_analyzer\base64_decoder.py
Inside print_analysis_result(), find the MITRE section. It probably ends like this:

if mitre_attack:
    print("\nMITRE ATT&CK Mapping:")
    print("------------------------------------")

    for technique in mitre_attack:
        print(
            f"- {technique.get('technique_id')} - {technique.get('technique_name')} "
            f"({technique.get('tactic')})"
        )
        print(f"  Reason: {technique.get('reason')}")

print()
Replace that ending with this:

if mitre_attack:
    print("\nMITRE ATT&CK Mapping:")
    print("------------------------------------")

    for technique in mitre_attack:
        print(
            f"- {technique.get('technique_id')} - {technique.get('technique_name')} "
            f"({technique.get('tactic')})"
        )
        print(f"  Reason: {technique.get('reason')}")

detection_rules = analysis.get("detection_rules", [])

if detection_rules:
    print("\nDetection Rule Mapping:")
    print("------------------------------------")

    for rule in detection_rules:
        print(f"- {rule.get('rule_name')}")
        print(f"  Severity: {rule.get('severity')}")
        print(f"  Description: {rule.get('description')}")
        print(f"  Log Sources: {', '.join(rule.get('log_sources', []))}")
        print(f"  Reason: {rule.get('reason')}")

print()
Step 2: Update GUI output in encoded_command_gui.py
Open:

C:\encoded_command_analyzer\encoded_command_gui.py
Inside display_analysis(), find the MITRE display section. It should look similar to this:

mitre_attack = analysis.get("mitre_attack", [])

if mitre_attack:
    self.output_box.insert(tk.END, "\nMITRE ATT&CK Mapping:\n")
    self.output_box.insert(tk.END, "------------------------------------\n")

    for technique in mitre_attack:
        self.output_box.insert(
            tk.END,
            f"- {technique.get('technique_id')} - {technique.get('technique_name')} "
            f"({technique.get('tactic')})\n"
        )
        self.output_box.insert(
            tk.END,
            f"  Reason: {technique.get('reason')}\n"
        )

self.output_box.insert(tk.END, "\n")
Replace that ending with this:

mitre_attack = analysis.get("mitre_attack", [])

if mitre_attack:
    self.output_box.insert(tk.END, "\nMITRE ATT&CK Mapping:\n")
    self.output_box.insert(tk.END, "------------------------------------\n")

    for technique in mitre_attack:
        self.output_box.insert(
            tk.END,
            f"- {technique.get('technique_id')} - {technique.get('technique_name')} "
            f"({technique.get('tactic')})\n"
        )
        self.output_box.insert(
            tk.END,
            f"  Reason: {technique.get('reason')}\n"
        )

detection_rules = analysis.get("detection_rules", [])

if detection_rules:
    self.output_box.insert(tk.END, "\nDetection Rule Mapping:\n")
    self.output_box.insert(tk.END, "------------------------------------\n")

    for rule in detection_rules:
        self.output_box.insert(tk.END, f"- {rule.get('rule_name')}\n")
        self.output_box.insert(tk.END, f"  Severity: {rule.get('severity')}\n")
        self.output_box.insert(tk.END, f"  Description: {rule.get('description')}\n")
        self.output_box.insert(
            tk.END,
            f"  Log Sources: {', '.join(rule.get('log_sources', []))}\n"
        )
        self.output_box.insert(tk.END, f"  Reason: {rule.get('reason')}\n")

self.output_box.insert(tk.END, "\n")
Step 3: Update CSV export in report_exporter.py
Open:

C:\encoded_command_analyzer\report_exporter.py
In export_to_csv(), add this field to the fieldnames list:

"detection_rules"
So the end should include:

"reasons",
"mitre_attack",
"detection_rules"
Then before writer.writerow({ ... }), add:

detection_rule_values = []

for rule in result.get("detection_rules", []):
    detection_rule_values.append(
        f"{rule.get('rule_name')} ({rule.get('severity')})"
    )
Then inside writer.writerow({ ... }), add:

"detection_rules": " | ".join(detection_rule_values)
Step 4: Update Markdown report in report_exporter.py
Inside export_to_markdown(), find the MITRE ATT&CK section. It probably ends like this:

if mitre_attack:
    for technique in mitre_attack:
        file.write(
            f"- {technique.get('technique_id')} - "
            f"{technique.get('technique_name')} "
            f"({technique.get('tactic')})\n"
        )
        file.write(f"  - Reason: {technique.get('reason')}\n")
else:
    file.write("- No MITRE ATT&CK mappings identified.\n")

file.write("\n---\n\n")
Replace that ending with this:

if mitre_attack:
    for technique in mitre_attack:
        file.write(
            f"- {technique.get('technique_id')} - "
            f"{technique.get('technique_name')} "
            f"({technique.get('tactic')})\n"
        )
        file.write(f"  - Reason: {technique.get('reason')}\n")
else:
    file.write("- No MITRE ATT&CK mappings identified.\n")

file.write("\n")

file.write("### Detection Rule Mapping\n\n")

detection_rules = result.get("detection_rules", [])

if detection_rules:
    for rule in detection_rules:
        file.write(f"- {rule.get('rule_name')}\n")
        file.write(f"  - Severity: {rule.get('severity')}\n")
        file.write(f"  - Description: {rule.get('description')}\n")
        file.write(f"  - Log Sources: {', '.join(rule.get('log_sources', []))}\n")
        file.write(f"  - Reason: {rule.get('reason')}\n")
else:
    file.write("- No detection rule mappings identified.\n")

file.write("\n---\n\n")
Step 5: Test CLI again
Run:

python base64_decoder.py --input "cG93ZXJzaGVsbCUyRWV4ZSUyMC1lbmMlMjBJRVg=" --export
Now the console should include:

Detection Rule Mapping:
------------------------------------
- Suspicious PowerShell EncodedCommand Execution
  Severity: High
  Log Sources: Microsoft Defender DeviceProcessEvents, Sysmon Event ID 1, Windows Security Event ID 4688
Then open the Markdown report:

notepad output\triage_report.md
You should see a Detection Rule Mapping section.

After that works, commit:

git status
git add .
git commit -m "Display detection rule mappings in reports"
git push

PS C:\encoded_command_analyzer> python base64_decoder.py --input "cG93ZXJzaGVsbCUyRWV4ZSUyMC1lbmMlMjBJRVg=" --export
====================================
Timestamp: 2026-05-19T18:03:58
Detected Encoding: UTF-8
Decode Level: 1

Decoded Output:
------------------------------------
powershell%2Eexe%20-enc%20IEX

Suspicious Keyword Check:
------------------------------------
- powershell
- -enc
- iex

Risk Score:
------------------------------------
Risk Level: High
Score: 7

Reasons:
- powershell may indicate suspicious command-line or PowerShell behavior.
- -enc may indicate suspicious command-line or PowerShell behavior.
- iex is commonly used in malicious or obfuscated script execution.

MITRE ATT&CK Mapping:
------------------------------------
- T1059.001 - PowerShell (Execution)
  Reason: PowerShell is commonly used for command and script execution.
- T1027 - Obfuscated Files or Information (Defense Evasion)
  Reason: Encoded command usage may indicate command obfuscation.

Detection Rule Mapping:
------------------------------------
- Suspicious PowerShell EncodedCommand Execution
  Severity: High
  Description: Detects PowerShell execution using encoded command indicators.
  Log Sources: Microsoft Defender DeviceProcessEvents, Sysmon Event ID 1, Windows Security Event ID 4688
  Reason: PowerShell execution with encoded command usage may indicate obfuscated script execution.
- PowerShell Invoke-Expression Usage
  Severity: Medium
  Description: Detects use of IEX or Invoke-Expression patterns.
  Log Sources: Microsoft Defender DeviceProcessEvents, PowerShell Script Block Logs, Sysmon Event ID 1
  Reason: IEX is commonly used to execute PowerShell content in memory.

====================================
Timestamp: 2026-05-19T18:03:58
Detected Encoding: URL
Decode Level: 2
Source Encoding: UTF-8

Decoded Output:
------------------------------------
powershell.exe -enc IEX

Suspicious Keyword Check:
------------------------------------
- powershell
- -enc
- iex

Risk Score:
------------------------------------
Risk Level: High
Score: 7

Reasons:
- powershell may indicate suspicious command-line or PowerShell behavior.
- -enc may indicate suspicious command-line or PowerShell behavior.
- iex is commonly used in malicious or obfuscated script execution.

MITRE ATT&CK Mapping:
------------------------------------
- T1059.001 - PowerShell (Execution)
  Reason: PowerShell is commonly used for command and script execution.
- T1027 - Obfuscated Files or Information (Defense Evasion)
  Reason: Encoded command usage may indicate command obfuscation.

Detection Rule Mapping:
------------------------------------
- Suspicious PowerShell EncodedCommand Execution
  Severity: High
  Description: Detects PowerShell execution using encoded command indicators.
  Log Sources: Microsoft Defender DeviceProcessEvents, Sysmon Event ID 1, Windows Security Event ID 4688
  Reason: PowerShell execution with encoded command usage may indicate obfuscated script execution.
- PowerShell Invoke-Expression Usage
  Severity: Medium
  Description: Detects use of IEX or Invoke-Expression patterns.
  Log Sources: Microsoft Defender DeviceProcessEvents, PowerShell Script Block Logs, Sysmon Event ID 1
  Reason: IEX is commonly used to execute PowerShell content in memory.

====================================
Analysis Summary
====================================
Total Results: 2
Highest Risk: High
Highest Score: 7
====================================

Export Complete:
- JSON:     output/analysis_result.json
- CSV:      output/analysis_result.csv
- Markdown: output/triage_report.md
PS C:\encoded_command_analyzer>

That output is exactly right. Version 20 is working now.

You successfully added:

Detection Rule Mapping
And it is correctly suggesting:

Suspicious PowerShell EncodedCommand Execution
PowerShell Invoke-Expression Usage
Now do a quick export check:

notepad output\triage_report.md
Make sure you see:

Detection Rule Mapping
Then open the CSV too if you want to verify the column:

notepad output\analysis_result.csv
After that, commit Version 20:

git status
git add .
git commit -m "Add detection rule mapping support"
git push
Next step should be updating the README for Version 20 so your GitHub page shows detection rule mapping as a current capability.


update readme for me

Thought for a couple of seconds
Replace your entire README.md with this Version 20 README:

# Encoded Command Analyzer

![Python](https://img.shields.io/badge/Python-3.x-blue)
![License: MIT](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)
![Project Type](https://img.shields.io/badge/Project-Detection%20Engineering-red)
![Interface](https://img.shields.io/badge/Interface-CLI%20%7C%20GUI-purple)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-orange)
![Detection Mapping](https://img.shields.io/badge/Detection-Rule%20Mapping-red)
![Exports](https://img.shields.io/badge/Exports-JSON%20%7C%20CSV%20%7C%20Markdown-yellow)
![Decoding](https://img.shields.io/badge/Decoding-Base64%20%7C%20URL%20%7C%20Hex%20%7C%20XOR-blueviolet)
![Testing](https://img.shields.io/badge/Testing-Unittest-brightgreen)
![Packaging](https://img.shields.io/badge/Packaging-PyInstaller-lightgrey)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)

## Overview

**Encoded Command Analyzer** is a Python-based detection engineering utility for decoding and analyzing encoded command-line content.

The tool is designed to help security analysts and detection engineers triage suspicious commands, identify signs of PowerShell abuse, detect common obfuscation patterns, map findings to MITRE ATT&CK techniques, suggest related detection rule ideas, and produce analyst-friendly output for investigations.

This project started as a simple Base64 decoder and has expanded into a lightweight encoded command analysis tool with CLI support, GUI support, batch file analysis, chained decoding, compressed Base64 support, XOR Hex decoding, suspicious keyword detection, risk scoring, MITRE ATT&CK mapping, detection rule mapping, analyst-ready exports, unit testing, and Windows executable packaging.

---

## Current Version

**Version 20**

### Current Capabilities

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
- Assign a risk level based on detected indicators
- Explain why a command may be suspicious
- Map suspicious indicators to MITRE ATT&CK techniques
- Suggest related detection rule ideas
- Identify possible log sources for detection engineering
- Export analysis results to JSON
- Export analysis results to CSV
- Export analyst triage reports to Markdown
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

Version 20 adds detection rule mapping.

This feature suggests related detection ideas based on suspicious keywords found in the decoded command. It helps connect decoded artifacts to practical detection engineering opportunities.

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
```

XOR Hex detection is confidence-based and intended to help analysts identify suspicious strings during triage.

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
- Review detection rule mappings
- Export results to JSON, CSV, and Markdown
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
├── tests/
│   ├── test_decoder_engine.py
│   └── test_detection_engine.py
├── output/
│   ├── analysis_result.json
│   ├── analysis_result.csv
│   └── triage_report.md
├── README.md
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
| `detection_engine.py` | Suspicious keyword detection, risk scoring, analysis logic, MITRE ATT&CK mapping, and detection rule mapping |
| `report_exporter.py` | JSON, CSV, and Markdown export functions |
| `samples/` | Sample input files for testing |
| `tests/` | Unit tests for decoder and detection logic |
| `output/` | Stores exported analysis results and triage reports |

---

## Requirements

This project currently uses Python standard libraries only.

No external packages are required for the analyzer itself.

Tested with:

```text
Python 3.x
```

For Windows executable packaging, PyInstaller is required:

```powershell
pip install pyinstaller
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

Version 19 added support for packaging the Tkinter GUI as a Windows executable using PyInstaller.

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
- Detection rule mappings

---

## Analyst Triage Report

The generated Markdown triage report includes:

- Summary
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

The report is saved to:

```text
output/triage_report.md
```

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
9. Review detection rule mappings.
10. Export results to JSON, CSV, or Markdown.
11. Attach output to triage notes or investigation documentation.
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

- Version 21: Add configurable keyword rules
- Version 22: Add HTML report export
- Version 23: Add enrichment fields for analyst notes
- Version 24: Add Sigma or Sentinel rule templates
- Version 25: Add detection coverage summary

---

## Disclaimer

This tool is intended for defensive security, detection engineering, malware analysis support, and security training purposes only.

Decoded content should always be reviewed carefully in a controlled environment.

---

## License

This project is licensed under the MIT License.
Then commit it:

git status
git add README.md
git commit -m "Update README for detection rule mapping"
git push

