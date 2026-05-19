import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

from decoder_engine import decode_input
from detection_engine import analyze_decoded_result
from report_exporter import export_to_csv, export_to_json, export_to_markdown


class EncodedCommandAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Encoded Command Analyzer")
        self.root.geometry("1000x750")
        self.root.configure(bg="#0f172a")

        self.analysis_results = []

        self.create_widgets()

    def create_widgets(self):
        title_label = tk.Label(
            self.root,
            text="Encoded Command Analyzer",
            font=("Arial", 22, "bold"),
            bg="#0f172a",
            fg="#e5e7eb"
        )
        title_label.pack(pady=(15, 5))

        subtitle_label = tk.Label(
            self.root,
            text="Decode Base64, PowerShell UTF-16LE, URL, Hex, and chained encoded command content",
            font=("Arial", 10),
            bg="#0f172a",
            fg="#94a3b8"
        )
        subtitle_label.pack(pady=(0, 15))

        input_frame = tk.Frame(self.root, bg="#1e293b", padx=15, pady=15)
        input_frame.pack(fill="x", padx=20, pady=10)

        input_label = tk.Label(
            input_frame,
            text="Paste encoded command or string:",
            font=("Arial", 11, "bold"),
            bg="#1e293b",
            fg="#e5e7eb"
        )
        input_label.pack(anchor="w")

        self.input_box = scrolledtext.ScrolledText(
            input_frame,
            height=7,
            wrap=tk.WORD,
            font=("Consolas", 10)
        )
        self.input_box.pack(fill="x", pady=(8, 0))

        button_frame = tk.Frame(self.root, bg="#0f172a")
        button_frame.pack(pady=10)

        analyze_button = tk.Button(
            button_frame,
            text="Analyze",
            width=18,
            bg="#2563eb",
            fg="white",
            font=("Arial", 10, "bold"),
            command=self.analyze_input
        )
        analyze_button.grid(row=0, column=0, padx=6)

        batch_button = tk.Button(
            button_frame,
            text="Load Batch File",
            width=18,
            bg="#7c3aed",
            fg="white",
            font=("Arial", 10, "bold"),
            command=self.load_batch_file
        )
        batch_button.grid(row=0, column=1, padx=6)

        clear_button = tk.Button(
            button_frame,
            text="Clear",
            width=18,
            bg="#475569",
            fg="white",
            font=("Arial", 10, "bold"),
            command=self.clear_all
        )
        clear_button.grid(row=0, column=2, padx=6)

        export_button = tk.Button(
            button_frame,
            text="Export JSON/CSV",
            width=18,
            bg="#16a34a",
            fg="white",
            font=("Arial", 10, "bold"),
            command=self.export_results
        )
        export_button.grid(row=0, column=3, padx=6)

        self.risk_banner = tk.Label(
            self.root,
            text="Risk Level: Not Analyzed",
            font=("Arial", 14, "bold"),
            bg="#334155",
            fg="white",
            padx=15,
            pady=10
        )
        self.risk_banner.pack(fill="x", padx=20, pady=(5, 10))

        output_frame = tk.Frame(self.root, bg="#1e293b", padx=15, pady=15)
        output_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        output_label = tk.Label(
            output_frame,
            text="Analysis Results:",
            font=("Arial", 11, "bold"),
            bg="#1e293b",
            fg="#e5e7eb"
        )
        output_label.pack(anchor="w")

        self.output_box = scrolledtext.ScrolledText(
            output_frame,
            height=25,
            wrap=tk.WORD,
            font=("Consolas", 10)
        )
        self.output_box.pack(fill="both", expand=True, pady=(8, 0))

    def analyze_input(self):
        encoded_text = self.input_box.get("1.0", tk.END).strip()

        if not encoded_text:
            messagebox.showwarning("Missing Input", "Please paste an encoded string first.")
            return

        decoded_results = decode_input(encoded_text)

        self.analysis_results = []
        self.output_box.delete("1.0", tk.END)

        highest_risk = "None"
        highest_score = 0

        for result in decoded_results:
            analysis = analyze_decoded_result(result)
            analysis["original_input"] = encoded_text

            self.analysis_results.append(analysis)
            self.display_analysis(analysis)

            if analysis.get("risk_score", 0) > highest_score:
                highest_score = analysis.get("risk_score", 0)
                highest_risk = analysis.get("risk_level", "None")

        self.update_risk_banner(highest_risk, highest_score)

    def load_batch_file(self):
        file_path = filedialog.askopenfilename(
            title="Select Batch File",
            filetypes=[
                ("Text Files", "*.txt"),
                ("CSV Files", "*.csv"),
                ("All Files", "*.*")
            ]
        )

        if not file_path:
            return

        try:
            with open(file_path, "r", encoding="utf-8") as file:
                lines = file.readlines()

            encoded_values = []

            for line in lines:
                cleaned_line = line.strip()

                if cleaned_line:
                    encoded_values.append(cleaned_line)

            if not encoded_values:
                messagebox.showwarning(
                    "Empty File",
                    "The selected file does not contain any encoded values."
                )
                return

            self.analyze_batch(encoded_values, file_path)

        except Exception as error:
            messagebox.showerror(
                "File Error",
                f"Could not read the selected file:\n\n{error}"
            )

    def analyze_batch(self, encoded_values, file_path):
        self.analysis_results = []
        self.output_box.delete("1.0", tk.END)

        highest_risk = "None"
        highest_score = 0

        self.output_box.insert(tk.END, "====================================\n")
        self.output_box.insert(tk.END, "Batch File Analysis\n")
        self.output_box.insert(tk.END, f"Source File: {file_path}\n")
        self.output_box.insert(tk.END, f"Total Inputs: {len(encoded_values)}\n")
        self.output_box.insert(tk.END, "====================================\n\n")

        for index, encoded_text in enumerate(encoded_values, start=1):
            self.output_box.insert(tk.END, f"\n########## Batch Item {index} ##########\n")
            self.output_box.insert(tk.END, f"Original Input:\n{encoded_text}\n\n")

            decoded_results = decode_input(encoded_text)

            for result in decoded_results:
                analysis = analyze_decoded_result(result)
                analysis["batch_item"] = index
                analysis["original_input"] = encoded_text
                analysis["source_file"] = file_path

                self.analysis_results.append(analysis)
                self.display_analysis(analysis)

                if analysis.get("risk_score", 0) > highest_score:
                    highest_score = analysis.get("risk_score", 0)
                    highest_risk = analysis.get("risk_level", "None")

        self.update_risk_banner(highest_risk, highest_score)

    def update_risk_banner(self, risk_level, score):
        colors = {
            "High": "#dc2626",
            "Medium": "#f97316",
            "Low": "#ca8a04",
            "None": "#16a34a"
        }

        banner_color = colors.get(risk_level, "#334155")

        self.risk_banner.config(
            text=f"Risk Level: {risk_level} | Score: {score}",
            bg=banner_color
        )

    def display_analysis(self, analysis):
        self.output_box.insert(tk.END, "====================================\n")
        self.output_box.insert(tk.END, f"Timestamp: {analysis.get('timestamp', '')}\n")
        self.output_box.insert(tk.END, f"Detected Encoding: {analysis.get('encoding', '')}\n")

        if "decode_level" in analysis:
            self.output_box.insert(tk.END, f"Decode Level: {analysis.get('decode_level')}\n")

        if "source_encoding" in analysis:
            self.output_box.insert(tk.END, f"Source Encoding: {analysis.get('source_encoding')}\n")

        self.output_box.insert(tk.END, "\nDecoded Output:\n")
        self.output_box.insert(tk.END, "------------------------------------\n")
        self.output_box.insert(tk.END, f"{analysis.get('decoded_text', '')}\n\n")

        self.output_box.insert(tk.END, "Suspicious Keyword Check:\n")
        self.output_box.insert(tk.END, "------------------------------------\n")

        suspicious_keywords = analysis.get("suspicious_keywords", [])

        if suspicious_keywords:
            for keyword in suspicious_keywords:
                self.output_box.insert(tk.END, f"- {keyword}\n")
        else:
            self.output_box.insert(tk.END, "No suspicious keywords found.\n")

        self.output_box.insert(tk.END, "\nRisk Score:\n")
        self.output_box.insert(tk.END, "------------------------------------\n")
        self.output_box.insert(tk.END, f"Risk Level: {analysis.get('risk_level', 'None')}\n")
        self.output_box.insert(tk.END, f"Score: {analysis.get('risk_score', 0)}\n")

        reasons = analysis.get("reasons", [])

        if reasons:
            self.output_box.insert(tk.END, "\nReasons:\n")

            for reason in reasons:
                self.output_box.insert(tk.END, f"- {reason}\n")

        mitre_attack = analysis.get("mitre_attack", [])

        if mitre_attack:
            self.output_box.insert(tk.END, "\nMITRE ATT&CK Mapping:\n")
            self.output_box.insert(tk.END, "------------------------------------\n")

            for technique in mitre_attack:
                self.output_box.insert(
                    tk.END,
                    f"- {technique.get('technique_id')} - {technique.get('technique_name')} "
                    f"({technique.get('tactic')})\n"
                )
                self.output_box.insert(
                    tk.END,
                    f"  Reason: {technique.get('reason')}\n"
                )

        detection_rules = analysis.get("detection_rules", [])

        if detection_rules:
            self.output_box.insert(tk.END, "\nDetection Rule Mapping:\n")
            self.output_box.insert(tk.END, "------------------------------------\n")

            for rule in detection_rules:
                self.output_box.insert(tk.END, f"- {rule.get('rule_name')}\n")
                self.output_box.insert(tk.END, f"  Severity: {rule.get('severity')}\n")
                self.output_box.insert(tk.END, f"  Description: {rule.get('description')}\n")
                self.output_box.insert(
                    tk.END,
                    f"  Log Sources: {', '.join(rule.get('log_sources', []))}\n"
                )
                self.output_box.insert(tk.END, f"  Reason: {rule.get('reason')}\n")

        self.output_box.insert(tk.END, "\n")

    def export_results(self):
        if not self.analysis_results:
            messagebox.showwarning(
                "No Results",
                "Run an analysis before exporting results."
            )
            return

        try:
            json_path = export_to_json(self.analysis_results)
            csv_path = export_to_csv(self.analysis_results)
            markdown_path = export_to_markdown(self.analysis_results)

            messagebox.showinfo(
                "Export Complete",
                f"Results exported successfully:\n\n{json_path}\n{csv_path}\n{markdown_path}"
            )

        except Exception as error:
            messagebox.showerror(
                "Export Error",
                f"Could not export results:\n\n{error}"
            )

    def clear_all(self):
        self.input_box.delete("1.0", tk.END)
        self.output_box.delete("1.0", tk.END)

        self.analysis_results = []

        self.risk_banner.config(
            text="Risk Level: Not Analyzed",
            bg="#334155"
        )


def main():
    root = tk.Tk()
    EncodedCommandAnalyzerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()