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
            "decode_level",
            "source_encoding",
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
                "timestamp": result.get("timestamp", ""),
                "encoding": result.get("encoding", ""),
                "decode_level": result.get("decode_level", ""),
                "source_encoding": result.get("source_encoding", ""),
                "decoded_text": result.get("decoded_text", ""),
                "suspicious_keywords": ", ".join(result.get("suspicious_keywords", [])),
                "risk_level": result.get("risk_level", ""),
                "risk_score": result.get("risk_score", ""),
                "reasons": " | ".join(result.get("reasons", []))
            })

    return file_path