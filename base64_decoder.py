import base64


def decode_base64(encoded_text):
    try:
        decoded_bytes = base64.b64decode(encoded_text)
        decoded_text = decoded_bytes.decode("utf-8", errors="ignore")
        return decoded_text
    except Exception as error:
        return f"Error decoding Base64: {error}"


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
        "hidden"
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
        "start-process"
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


def main():
    print("====================================")
    print(" Encoded Command Analyzer - Version 3")
    print("====================================")

    encoded_text = input("Paste Base64 string: ")

    decoded_text = decode_base64(encoded_text)

    print("\nDecoded Output:")
    print("------------------------------------")
    print(decoded_text)

    found_keywords = check_suspicious_keywords(decoded_text)

    print("\nSuspicious Keyword Check:")
    print("------------------------------------")

    if found_keywords:
        print("Suspicious keywords found:")
        for keyword in found_keywords:
            print(f"- {keyword}")
    else:
        print("No suspicious keywords found.")

    risk_level, score, reasons = calculate_risk_score(found_keywords)

    print("\nRisk Score:")
    print("------------------------------------")
    print(f"Risk Level: {risk_level}")
    print(f"Score: {score}")

    if reasons:
        print("\nReasons:")
        for reason in reasons:
            print(f"- {reason}")


if __name__ == "__main__":
    main()