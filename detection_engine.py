import json
import os
from datetime import datetime


DEFAULT_KEYWORD_RULES = [
    {
        "keyword": "powershell",
        "severity": "Medium",
        "score": 2,
        "reason": "powershell may indicate suspicious command-line or PowerShell behavior."
    },
    {
        "keyword": "-enc",
        "severity": "High",
        "score": 2,
        "reason": "-enc may indicate suspicious command-line or PowerShell behavior."
    },
    {
        "keyword": "-encodedcommand",
        "severity": "High",
        "score": 2,
        "reason": "-encodedcommand may indicate encoded PowerShell command execution."
    },
    {
        "keyword": "iex",
        "severity": "High",
        "score": 3,
        "reason": "iex is commonly used in malicious or obfuscated script execution."
    },
    {
        "keyword": "invoke-expression",
        "severity": "High",
        "score": 3,
        "reason": "Invoke-Expression is commonly used to execute PowerShell expressions or downloaded content."
    },
    {
        "keyword": "downloadstring",
        "severity": "High",
        "score": 3,
        "reason": "DownloadString may indicate remote payload retrieval."
    },
    {
        "keyword": "frombase64string",
        "severity": "Medium",
        "score": 2,
        "reason": "FromBase64String may indicate embedded encoded payload content."
    },
    {
        "keyword": "webclient",
        "severity": "Medium",
        "score": 2,
        "reason": "WebClient may be used to download remote tools or payloads."
    },
    {
        "keyword": "start-process",
        "severity": "Medium",
        "score": 1,
        "reason": "Start-Process may indicate child process execution."
    },
    {
        "keyword": "cmd.exe",
        "severity": "Low",
        "score": 1,
        "reason": "cmd.exe may provide useful command-line execution context."
    },
    {
        "keyword": "http",
        "severity": "Medium",
        "score": 1,
        "reason": "HTTP may indicate remote resource or payload access."
    },
    {
        "keyword": "https",
        "severity": "Medium",
        "score": 1,
        "reason": "HTTPS may indicate remote resource or payload access."
    },
    {
        "keyword": "bypass",
        "severity": "High",
        "score": 2,
        "reason": "Bypass may indicate attempts to evade execution policy or security controls."
    },
    {
        "keyword": "hidden",
        "severity": "Medium",
        "score": 2,
        "reason": "Hidden execution may indicate an attempt to conceal command activity."
    },
    {
        "keyword": "nop",
        "severity": "Medium",
        "score": 1,
        "reason": "NoProfile usage may indicate an attempt to avoid loading normal PowerShell profile settings."
    },
    {
        "keyword": "wscript",
        "severity": "Medium",
        "score": 2,
        "reason": "wscript can execute script content on Windows systems."
    },
    {
        "keyword": "cscript",
        "severity": "Medium",
        "score": 2,
        "reason": "cscript can execute script content on Windows systems."
    }
]


def load_keyword_rules():
    config_path = os.path.join("config", "keyword_rules.json")

    if not os.path.exists(config_path):
        return DEFAULT_KEYWORD_RULES

    try:
        with open(config_path, "r", encoding="utf-8") as file:
            config = json.load(file)

        rules = config.get("keywords", [])

        if not rules:
            return DEFAULT_KEYWORD_RULES

        return rules

    except Exception:
        return DEFAULT_KEYWORD_RULES

def check_suspicious_keywords(decoded_text):
    keyword_rules = load_keyword_rules()
    decoded_text_lower = decoded_text.lower()

    found_keywords = []

    for rule in keyword_rules:
        keyword = rule.get("keyword", "").lower()

        if keyword and keyword in decoded_text_lower:
            found_keywords.append(keyword)

    return found_keywords


def calculate_risk_score(found_keywords):
    keyword_rules = load_keyword_rules()
    keyword_rule_map = {}

    for rule in keyword_rules:
        keyword_rule_map[rule.get("keyword", "").lower()] = rule

    score = 0
    reasons = []

    for keyword in found_keywords:
        rule = keyword_rule_map.get(keyword.lower())

        if rule:
            score += int(rule.get("score", 1))
            reasons.append(rule.get("reason", f"{keyword} matched a suspicious keyword."))

    if score >= 6:
        risk_level = "High"
    elif score >= 3:
        risk_level = "Medium"
    elif score >= 1:
        risk_level = "Low"
    else:
        risk_level = "None"

    return risk_level, score, reasons
    
def map_mitre_attack(found_keywords):
    mitre_mappings = []

    keyword_to_mitre = {
        "powershell": {
            "technique_id": "T1059.001",
            "technique_name": "PowerShell",
            "tactic": "Execution",
            "reason": "PowerShell is commonly used for command and script execution."
        },
        "-enc": {
            "technique_id": "T1027",
            "technique_name": "Obfuscated Files or Information",
            "tactic": "Defense Evasion",
            "reason": "Encoded command usage may indicate command obfuscation."
        },
        "-encodedcommand": {
            "technique_id": "T1027",
            "technique_name": "Obfuscated Files or Information",
            "tactic": "Defense Evasion",
            "reason": "EncodedCommand usage may indicate command obfuscation."
        },
        "iex": {
            "technique_id": "T1059.001",
            "technique_name": "PowerShell",
            "tactic": "Execution",
            "reason": "IEX is commonly used to execute PowerShell content in memory."
        },
        "invoke-expression": {
            "technique_id": "T1059.001",
            "technique_name": "PowerShell",
            "tactic": "Execution",
            "reason": "Invoke-Expression executes PowerShell expressions or downloaded content."
        },
        "downloadstring": {
            "technique_id": "T1105",
            "technique_name": "Ingress Tool Transfer",
            "tactic": "Command and Control",
            "reason": "DownloadString may indicate remote payload retrieval."
        },
        "webclient": {
            "technique_id": "T1105",
            "technique_name": "Ingress Tool Transfer",
            "tactic": "Command and Control",
            "reason": "WebClient may be used to download remote tools or payloads."
        },
        "frombase64string": {
            "technique_id": "T1027",
            "technique_name": "Obfuscated Files or Information",
            "tactic": "Defense Evasion",
            "reason": "FromBase64String may indicate embedded or decoded payload content."
        },
        "bypass": {
            "technique_id": "T1562.001",
            "technique_name": "Disable or Modify Tools",
            "tactic": "Defense Evasion",
            "reason": "Bypass may indicate attempts to evade execution policy or security controls."
        },
        "hidden": {
            "technique_id": "T1564.003",
            "technique_name": "Hidden Window",
            "tactic": "Defense Evasion",
            "reason": "Hidden execution may indicate an attempt to conceal command activity."
        },
        "cmd.exe": {
            "technique_id": "T1059.003",
            "technique_name": "Windows Command Shell",
            "tactic": "Execution",
            "reason": "cmd.exe is commonly used for command-line execution."
        },
        "wscript": {
            "technique_id": "T1059.005",
            "technique_name": "Visual Basic",
            "tactic": "Execution",
            "reason": "wscript can execute script content on Windows systems."
        },
        "cscript": {
            "technique_id": "T1059.005",
            "technique_name": "Visual Basic",
            "tactic": "Execution",
            "reason": "cscript can execute script content on Windows systems."
        },
        "http": {
            "technique_id": "T1105",
            "technique_name": "Ingress Tool Transfer",
            "tactic": "Command and Control",
            "reason": "HTTP may indicate remote resource or payload access."
        },
        "https": {
            "technique_id": "T1105",
            "technique_name": "Ingress Tool Transfer",
            "tactic": "Command and Control",
            "reason": "HTTPS may indicate remote resource or payload access."
        }
    }

    seen_techniques = set()

    for keyword in found_keywords:
        mapping = keyword_to_mitre.get(keyword)

        if mapping:
            unique_key = f"{mapping['technique_id']}:{mapping['technique_name']}"

            if unique_key not in seen_techniques:
                seen_techniques.add(unique_key)
                mitre_mappings.append(mapping)

    return mitre_mappings

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