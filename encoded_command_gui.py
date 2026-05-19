import tkinter as tk
from tkinter import messagebox, scrolledtext

from decoder_engine import decode_input
from detection_engine import analyze_decoded_result
from report_exporter import export_to_csv, export_to_json


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

        clear_button = tk.Button(
            button_frame,
            text="Clear",
            width=18,
            bg="#475569",
            fg="white",
            font=("Arial", 10, "bold"),
            command=self.clear_all
        )
        clear_button.grid(row=0, column=1, padx=6)

        export_button = tk.Button(
            button_frame,
            text="Export JSON/CSV",
            width=18,
            bg="#16a34a",
            fg="white",
            font=("Arial", 10, "bold"),
            command=self.export_results
        )
        export_button.grid(row=0, column=2, padx=6)

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
            self.analysis_results.append(analysis)
            self.display_analysis(analysis)

            if analysis["risk_score"] > highest_score:
                highest_score = analysis["risk_score"]
                highest_risk = analysis["risk_level"]

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
        self.output_box.insert(tk.END, f"Timestamp: {analysis['timestamp']}\n")
        self.output_box.insert(tk.END, f"Detected Encoding: {analysis['encoding']}\n")

        if "decode_level" in analysis:
            self.output_box.insert(tk.END, f"Decode Level: {analysis['decode_level']}\n")

        if "source_encoding" in analysis:
            self.output_box.insert(tk.END, f"Source Encoding: {analysis['source_encoding']}\n")

        self.output_box.insert(tk.END, "\nDecoded Output:\n")
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