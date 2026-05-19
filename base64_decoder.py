import argparse
import subprocess
import sys

from decoder_engine import decode_input
from detection_engine import analyze_decoded_result
from report_exporter import export_to_csv, export_to_json, export_to_markdown


def print_analysis_result(analysis):
    print("====================================")
    print(f"Timestamp: {analysis.get('timestamp', '')}")
    print(f"Detected Encoding: {analysis.get('encoding', '')}")

    if "decode_level" in analysis:
        print(f"Decode Level: {analysis.get('decode_level')}")

    if "source_encoding" in analysis:
        print(f"Source Encoding: {analysis.get('source_encoding')}")

    if "batch_item" in analysis:
        print(f"Batch Item: {analysis.get('batch_item')}")

    print("\nDecoded Output:")
    print("------------------------------------")
    print(analysis.get("decoded_text", ""))

    print("\nSuspicious Keyword Check:")
    print("------------------------------------")

    suspicious_keywords = analysis.get("suspicious_keywords", [])

    if suspicious_keywords:
        for keyword in suspicious_keywords:
            print(f"- {keyword}")
    else:
        print("No suspicious keywords found.")

    print("\nRisk Score:")
    print("------------------------------------")
    print(f"Risk Level: {analysis.get('risk_level', 'None')}")
    print(f"Score: {analysis.get('risk_score', 0)}")

    reasons = analysis.get("reasons", [])

    if reasons:
        print("\nReasons:")
        for reason in reasons:
            print(f"- {reason}")

    mitre_attack = analysis.get("mitre_attack", [])

    if mitre_attack:
        print("\nMITRE ATT&CK Mapping:")
        print("------------------------------------")

        for technique in mitre_attack:
            print(
                f"- {technique.get('technique_id')} - {technique.get('technique_name')} "
                f"({technique.get('tactic')})"
            )
            print(f"  Reason: {technique.get('reason')}")

    print()


def analyze_single_input(encoded_text):
    decoded_results = decode_input(encoded_text)

    analysis_results = []

    for result in decoded_results:
        analysis = analyze_decoded_result(result)
        analysis["original_input"] = encoded_text
        analysis_results.append(analysis)

    return analysis_results


def analyze_batch_file(file_path):
    analysis_results = []

    try:
        with open(file_path, "r", encoding="utf-8") as file:
            lines = file.readlines()

        encoded_values = []

        for line in lines:
            cleaned_line = line.strip()

            if cleaned_line:
                encoded_values.append(cleaned_line)

        if not encoded_values:
            print(f"No encoded values found in file: {file_path}")
            return []

        for index, encoded_text in enumerate(encoded_values, start=1):
            decoded_results = decode_input(encoded_text)

            for result in decoded_results:
                analysis = analyze_decoded_result(result)
                analysis["batch_item"] = index
                analysis["original_input"] = encoded_text
                analysis["source_file"] = file_path
                analysis_results.append(analysis)

        return analysis_results

    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return []

    except Exception as error:
        print(f"Error reading file: {error}")
        return []


def print_summary(analysis_results):
    if not analysis_results:
        print("No analysis results generated.")
        return

    highest_score = 0
    highest_risk = "None"

    for result in analysis_results:
        score = result.get("risk_score", 0)

        if score > highest_score:
            highest_score = score
            highest_risk = result.get("risk_level", "None")

    print("====================================")
    print("Analysis Summary")
    print("====================================")
    print(f"Total Results: {len(analysis_results)}")
    print(f"Highest Risk: {highest_risk}")
    print(f"Highest Score: {highest_score}")
    print("====================================")


def export_results(analysis_results):
    if not analysis_results:
        print("No results to export.")
        return

    json_path = export_to_json(analysis_results)
    csv_path = export_to_csv(analysis_results)
    markdown_path = export_to_markdown(analysis_results)

    print("\nExport Complete:")
    print(f"- JSON:     {json_path}")
    print(f"- CSV:      {csv_path}")
    print(f"- Markdown: {markdown_path}")


def launch_gui():
    try:
        subprocess.run([sys.executable, "encoded_command_gui.py"], check=True)

    except FileNotFoundError:
        print("Could not find encoded_command_gui.py.")

    except Exception as error:
        print(f"Could not launch GUI: {error}")


def build_parser():
    parser = argparse.ArgumentParser(
        description="Encoded Command Analyzer - Decode and analyze encoded command-line content."
    )

    parser.add_argument(
        "--input",
        help="Analyze a single encoded string."
    )

    parser.add_argument(
        "--file",
        help="Analyze a batch file containing one encoded value per line."
    )

    parser.add_argument(
        "--export",
        action="store_true",
        help="Export analysis results to JSON and CSV."
    )

    parser.add_argument(
        "--gui",
        action="store_true",
        help="Launch the Tkinter GUI."
    )

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.gui:
        launch_gui()
        return

    if args.input and args.file:
        print("Use either --input or --file, not both.")
        return

    analysis_results = []

    if args.input:
        analysis_results = analyze_single_input(args.input)

    elif args.file:
        analysis_results = analyze_batch_file(args.file)

    else:
        print("No input provided.")
        print()
        parser.print_help()
        return

    for analysis in analysis_results:
        print_analysis_result(analysis)

    print_summary(analysis_results)

    if args.export:
        export_results(analysis_results)


if __name__ == "__main__":
    main()