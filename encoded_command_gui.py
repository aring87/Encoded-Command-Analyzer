import tkinter as tk
from tkinter import messagebox, scrolledtext

from decoder_engine import decode_input
from detection_engine import analyze_decoded_result
from report_exporter import export_to_csv, export_to_json


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
            width=18,
            command=self.analyze_input
        )
        analyze_button.grid(row=0, column=0, padx=5)

        clear_button = tk.Button(
            button_frame,
            text="Clear",
            width=18,
            command=self.clear_all
        )
        clear_button.grid(row=0, column=1, padx=5)

        export_button = tk.Button(
            button_frame,
            text="Export JSON/CSV",
            width=18,
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

        decoded_results = decode_input(encoded_text)

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
    EncodedCommandAnalyzerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()