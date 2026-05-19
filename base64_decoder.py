from decoder_engine import decode_input
from detection_engine import analyze_decoded_result
from report_exporter import export_to_csv, export_to_json


def decode_base64(encoded_text):
    try:
        decoded_bytes = base64.b64decode(encoded_text)

        decoded_results = []

        # First try UTF-16LE because PowerShell EncodedCommand commonly uses it
        try:
            utf16_text = decoded_bytes.decode("utf-16le")

            # If the decoded text looks readable, prefer UTF-16LE
            if any(keyword in utf16_text.lower() for keyword in ["powershell", "-enc", "iex", "cmd", "http"]):
                decoded_results.append({
                    "encoding": "UTF-16LE",
                    "decoded_text": utf16_text
                })
                return decoded_results

        except UnicodeDecodeError:
            pass

        # Then try normal UTF-8 Base64
        try:
            utf8_text = decoded_bytes.decode("utf-8")

            # Ignore UTF-8 results that contain lots of null-byte spacing
            if "\x00" not in utf8_text:
                decoded_results.append({
                    "encoding": "UTF-8",
                    "decoded_text": utf8_text
                })

        except UnicodeDecodeError:
            pass

        # If UTF-16LE worked but did not match keywords, still show it if readable
        try:
            utf16_text = decoded_bytes.decode("utf-16le")

            if "\x00" not in utf16_text and utf16_text.strip():
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


class EncodedCommandAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Encoded Command Analyzer")
        self.root.geometry("900x700")

        self.analysis_results = []

        title_label = tk.Label(
            root,
            text="Encoded Command Analyzer",
            font=("Arial", 18, "bold")
        )
        title_label.pack(pady=10)

        input_label = tk.Label(
            root,
            text="Paste Base64 or PowerShell EncodedCommand value:"
        )
        input_label.pack(anchor="w", padx=20)

        self.input_box = scrolledtext.ScrolledText(root, height=8, wrap=tk.WORD)
        self.input_box.pack(fill="both", padx=20, pady=5)

        button_frame = tk.Frame(root)
        button_frame.pack(pady=10)

        analyze_button = tk.Button(
            button_frame,
            text="Analyze",
            width=15,
            command=self.analyze_input
        )
        analyze_button.grid(row=0, column=0, padx=5)

        clear_button = tk.Button(
            button_frame,
            text="Clear",
            width=15,
            command=self.clear_all
        )
        clear_button.grid(row=0, column=1, padx=5)

        export_button = tk.Button(
            button_frame,
            text="Export JSON/CSV",
            width=15,
            command=self.export_results
        )
        export_button.grid(row=0, column=2, padx=5)

        output_label = tk.Label(root, text="Analysis Results:")
        output_label.pack(anchor="w", padx=20)

        self.output_box = scrolledtext.ScrolledText(root, height=25, wrap=tk.WORD)
        self.output_box.pack(fill="both", expand=True, padx=20, pady=5)

    def analyze_input(self):
        encoded_text = self.input_box.get("1.0", tk.END).strip()

        if not encoded_text:
            messagebox.showwarning("Missing Input", "Please paste an encoded string first.")
            return

        decoded_results = decode_base64(encoded_text)

        self.analysis_results = []
        self.output_box.delete("1.0", tk.END)

        for result in decoded_results:
            analysis = analyze_decoded_result(result)
            self.analysis_results.append(analysis)
            self.display_analysis(analysis)

    def display_analysis(self, analysis):
        self.output_box.insert(tk.END, "====================================\n")
        self.output_box.insert(tk.END, f"Timestamp: {analysis['timestamp']}\n")
        self.output_box.insert(tk.END, f"Detected Encoding: {analysis['encoding']}\n\n")

        self.output_box.insert(tk.END, "Decoded Output:\n")
        self.output_box.insert(tk.END, "------------------------------------\n")
        self.output_box.insert(tk.END, f"{analysis['decoded_text']}\n\n")

        self.output_box.insert(tk.END, "Suspicious Keyword Check:\n")
        self.output_box.insert(tk.END, "------------------------------------\n")

        if analysis["suspicious_keywords"]:
            for keyword in analysis["suspicious_keywords"]:
                self.output_box.insert(tk.END, f"- {keyword}\n")
        else:
            self.output_box.insert(tk.END, "No suspicious keywords found.\n")

        self.output_box.insert(tk.END, "\nRisk Score:\n")
        self.output_box.insert(tk.END, "------------------------------------\n")
        self.output_box.insert(tk.END, f"Risk Level: {analysis['risk_level']}\n")
        self.output_box.insert(tk.END, f"Score: {analysis['risk_score']}\n")

        if analysis["reasons"]:
            self.output_box.insert(tk.END, "\nReasons:\n")
            for reason in analysis["reasons"]:
                self.output_box.insert(tk.END, f"- {reason}\n")

        self.output_box.insert(tk.END, "\n")

    def export_results(self):
        if not self.analysis_results:
            messagebox.showwarning("No Results", "Run an analysis before exporting results.")
            return

        json_path = export_to_json(self.analysis_results)
        csv_path = export_to_csv(self.analysis_results)

        messagebox.showinfo(
            "Export Complete",
            f"Results exported successfully:\n\n{json_path}\n{csv_path}"
        )

    def clear_all(self):
        self.input_box.delete("1.0", tk.END)
        self.output_box.delete("1.0", tk.END)
        self.analysis_results = []


def main():
    root = tk.Tk()
    app = EncodedCommandAnalyzerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()