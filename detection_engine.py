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


def analyze_decoded_result(result):
    decoded_text = result["decoded_text"]
    found_keywords = check_suspicious_keywords(decoded_text)
    risk_level, score, reasons = calculate_risk_score(found_keywords)

    return {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "encoding": result["encoding"],
        "decoded_text": decoded_text,
        "suspicious_keywords": found_keywords,
        "risk_level": risk_level,
        "risk_score": score,
        "reasons": reasons
    }