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
            "batch_item",
            "source_file",
            "original_input",
            "encoding",
            "decode_level",
            "source_encoding",
            "decoded_text",
            "suspicious_keywords",
            "risk_level",
            "risk_score",
            "reasons",
            "mitre_attack"
        ]

        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()

        for result in analysis_results:
            mitre_values = []

            for technique in result.get("mitre_attack", []):
                mitre_values.append(
                    f"{technique.get('technique_id')} - {technique.get('technique_name')} "
                    f"({technique.get('tactic')})"
                )

            writer.writerow({
                "timestamp": result.get("timestamp", ""),
                "batch_item": result.get("batch_item", ""),
                "source_file": result.get("source_file", ""),
                "original_input": result.get("original_input", ""),
                "encoding": result.get("encoding", ""),
                "decode_level": result.get("decode_level", ""),
                "source_encoding": result.get("source_encoding", ""),
                "decoded_text": result.get("decoded_text", ""),
                "suspicious_keywords": ", ".join(result.get("suspicious_keywords", [])),
                "risk_level": result.get("risk_level", ""),
                "risk_score": result.get("risk_score", ""),
                "reasons": " | ".join(result.get("reasons", [])),
                "mitre_attack": " | ".join(mitre_values)
            })

    return file_path