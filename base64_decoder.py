import base64


def decode_base64(encoded_text):
    try:
        decoded_bytes = base64.b64decode(encoded_text)

        decoded_results = []

        try:
            utf8_text = decoded_bytes.decode("utf-8")
            decoded_results.append({
                "encoding": "UTF-8",
                "decoded_text": utf8_text
            })
        except UnicodeDecodeError:
            pass

        try:
            utf16_text = decoded_bytes.decode("utf-16le")
            decoded_results.append({
                "encoding": "UTF-16LE",
                "decoded_text": utf16_text
            })
        except UnicodeDecodeError:
            pass

        if not decoded_results:
            decoded_results.append({
                "encoding": "Unknown",
                "decoded_text": decoded_bytes.decode("utf-8", errors="ignore")
            })

        return decoded_results

    except Exception as error:
        return [{
            "encoding": "Error",
            "decoded_text": f"Error decoding Base64: {error}"
        }]


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


def print_analysis_result(result):
    encoding = result["encoding"]
    decoded_text = result["decoded_text"]

    print("\nDecoded Output:")
    print("------------------------------------")
    print(f"Detected Encoding: {encoding}")
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


def main():
    print("====================================")
    print(" Encoded Command Analyzer - Version 4")
    print("====================================")

    encoded_text = input("Paste Base64 string: ")

    decoded_results = decode_base64(encoded_text)

    for result in decoded_results:
        print_analysis_result(result)
        print("\n" + "=" * 50)


if __name__ == "__main__":
    main()