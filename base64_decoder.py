import base64
import json
import csv
import os
from datetime import datetime


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


def print_analysis_result(analysis):
    print("\nDecoded Output:")
    print("------------------------------------")
    print(f"Detected Encoding: {analysis['encoding']}")
    print(analysis["decoded_text"])

    print("\nSuspicious Keyword Check:")
    print("------------------------------------")

    if analysis["suspicious_keywords"]:
        print("Suspicious keywords found:")
        for keyword in analysis["suspicious_keywords"]:
            print(f"- {keyword}")
    else:
        print("No suspicious keywords found.")

    print("\nRisk Score:")
    print("------------------------------------")
    print(f"Risk Level: {analysis['risk_level']}")
    print(f"Score: {analysis['risk_score']}")

    if analysis["reasons"]:
        print("\nReasons:")
        for reason in analysis["reasons"]:
            print(f"- {reason}")


def export_to_json(analysis_results):
    os.makedirs("output", exist_ok=True)

    file_path = "output/analysis_result.json"

    with open(file_path, "w", encoding="utf-8") as file:
        json.dump(analysis_results, file, indent=4)

    print(f"\nJSON export saved to: {file_path}")


def export_to_csv(analysis_results):
    os.makedirs("output", exist_ok=True)

    file_path = "output/analysis_result.csv"

    with open(file_path, "w", newline="", encoding="utf-8") as file:
        fieldnames = [
            "timestamp",
            "encoding",
            "decoded_text",
            "suspicious_keywords",
            "risk_level",
            "risk_score",
            "reasons"
        ]

        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()

        for result in analysis_results:
            writer.writerow({
                "timestamp": result["timestamp"],
                "encoding": result["encoding"],
                "decoded_text": result["decoded_text"],
                "suspicious_keywords": ", ".join(result["suspicious_keywords"]),
                "risk_level": result["risk_level"],
                "risk_score": result["risk_score"],
                "reasons": " | ".join(result["reasons"])
            })

    print(f"CSV export saved to: {file_path}")


def main():
    print("====================================")
    print(" Encoded Command Analyzer - Version 5")
    print("====================================")

    encoded_text = input("Paste Base64 string: ")

    decoded_results = decode_base64(encoded_text)

    analysis_results = []

    for result in decoded_results:
        analysis = analyze_decoded_result(result)
        analysis_results.append(analysis)

        print_analysis_result(analysis)
        print("\n" + "=" * 50)

    export_choice = input("\nExport results to JSON and CSV? y/n: ").lower()

    if export_choice == "y":
        export_to_json(analysis_results)
        export_to_csv(analysis_results)
    else:
        print("Export skipped.")


if __name__ == "__main__":
    main()