from datetime import datetime


def check_suspicious_keywords(decoded_text):
    suspicious_keywords = [
        "powershell",
        "-enc",
        "-encodedcommand",
        "iex",
        "invoke-expression",
        "downloadstring",
        "frombase64string",
        "webclient",
        "start-process",
        "cmd.exe",
        "http",
        "https",
        "bypass",
        "hidden",
        "nop",
        "wscript",
        "cscript"
    ]

    found_keywords = []

    for keyword in suspicious_keywords:
        if keyword in decoded_text.lower():
            found_keywords.append(keyword)

    return found_keywords


def calculate_risk_score(found_keywords):
    score = 0
    reasons = []

    high_risk_keywords = [
        "iex",
        "invoke-expression",
        "downloadstring",
        "frombase64string",
        "webclient"
    ]

    medium_risk_keywords = [
        "powershell",
        "-enc",
        "-encodedcommand",
        "bypass",
        "hidden",
        "start-process",
        "nop",
        "wscript",
        "cscript"
    ]

    low_risk_keywords = [
        "cmd.exe",
        "http",
        "https"
    ]

    for keyword in found_keywords:
        if keyword in high_risk_keywords:
            score += 3
            reasons.append(f"{keyword} is commonly used in malicious or obfuscated script execution.")
        elif keyword in medium_risk_keywords:
            score += 2
            reasons.append(f"{keyword} may indicate suspicious command-line or PowerShell behavior.")
        elif keyword in low_risk_keywords:
            score += 1
            reasons.append(f"{keyword} may provide useful investigation context.")

    if score >= 6:
        risk_level = "High"
    elif score >= 3:
        risk_level = "Medium"
    elif score > 0:
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


def analyze_decoded_result(result):
    decoded_text = result["decoded_text"]
    found_keywords = check_suspicious_keywords(decoded_text)
    risk_level, score, reasons = calculate_risk_score(found_keywords)
    mitre_mappings = map_mitre_attack(found_keywords)

    analysis = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "encoding": result["encoding"],
        "decoded_text": decoded_text,
        "suspicious_keywords": found_keywords,
        "risk_level": risk_level,
        "risk_score": score,
        "reasons": reasons,
        "mitre_attack": mitre_mappings
    }

    if "decode_level" in result:
        analysis["decode_level"] = result["decode_level"]

    if "source_encoding" in result:
        analysis["source_encoding"] = result["source_encoding"]

    return analysis