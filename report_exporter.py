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
    
def export_to_markdown(analysis_results):
    os.makedirs("output", exist_ok=True)

    file_path = "output/triage_report.md"

    highest_score = 0
    highest_risk = "None"

    for result in analysis_results:
        score = result.get("risk_score", 0)

        if score > highest_score:
            highest_score = score
            highest_risk = result.get("risk_level", "None")

    with open(file_path, "w", encoding="utf-8") as file:
        file.write("# Encoded Command Analyzer Triage Report\n\n")

        file.write("## Summary\n\n")
        file.write(f"- Total Results: {len(analysis_results)}\n")
        file.write(f"- Highest Risk: {highest_risk}\n")
        file.write(f"- Highest Score: {highest_score}\n\n")

        file.write("---\n\n")

        for index, result in enumerate(analysis_results, start=1):
            file.write(f"## Finding {index}\n\n")

            file.write("### Metadata\n\n")
            file.write(f"- Timestamp: {result.get('timestamp', '')}\n")
            file.write(f"- Encoding: {result.get('encoding', '')}\n")
            file.write(f"- Decode Level: {result.get('decode_level', '')}\n")
            file.write(f"- Source Encoding: {result.get('source_encoding', '')}\n")
            file.write(f"- Batch Item: {result.get('batch_item', '')}\n")
            file.write(f"- Source File: {result.get('source_file', '')}\n\n")

            file.write("### Original Input\n\n")
            file.write("```text\n")
            file.write(f"{result.get('original_input', '')}\n")
            file.write("```\n\n")

            file.write("### Decoded Output\n\n")
            file.write("```text\n")
            file.write(f"{result.get('decoded_text', '')}\n")
            file.write("```\n\n")

            file.write("### Suspicious Keywords\n\n")

            suspicious_keywords = result.get("suspicious_keywords", [])

            if suspicious_keywords:
                for keyword in suspicious_keywords:
                    file.write(f"- {keyword}\n")
            else:
                file.write("- None\n")

            file.write("\n")

            file.write("### Risk Score\n\n")
            file.write(f"- Risk Level: {result.get('risk_level', 'None')}\n")
            file.write(f"- Score: {result.get('risk_score', 0)}\n\n")

            file.write("### Risk Reasons\n\n")

            reasons = result.get("reasons", [])

            if reasons:
                for reason in reasons:
                    file.write(f"- {reason}\n")
            else:
                file.write("- No risk reasons generated.\n")

            file.write("\n")

            file.write("### MITRE ATT&CK Mapping\n\n")

            mitre_attack = result.get("mitre_attack", [])

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

    return file_path