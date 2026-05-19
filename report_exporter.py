import csv
import json
import os


def export_to_json(analysis_results):
    os.makedirs("output", exist_ok=True)

    file_path = "output/analysis_result.json"

    with open(file_path, "w", encoding="utf-8") as file:
        json.dump(analysis_results, file, indent=4)

    return file_path


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

    return file_path