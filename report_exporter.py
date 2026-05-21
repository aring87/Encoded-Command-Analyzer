import csv
import json
import os

def build_detection_coverage_summary(analysis_results):
    mitre_techniques = {}
    detection_rules = {}
    detection_templates = {}

    for result in analysis_results:
        for technique in result.get("mitre_attack", []):
            technique_id = technique.get("technique_id", "")
            technique_name = technique.get("technique_name", "")
            tactic = technique.get("tactic", "")

            if technique_id:
                mitre_techniques[technique_id] = {
                    "technique_name": technique_name,
                    "tactic": tactic
                }

        for rule in result.get("detection_rules", []):
            rule_name = rule.get("rule_name", "")
            severity = rule.get("severity", "")

            if rule_name:
                detection_rules[rule_name] = severity

        for template in result.get("detection_templates", []):
            template_name = template.get("template_name", "")
            template_type = template.get("template_type", "")
            severity = template.get("severity", "")

            if template_name:
                detection_templates[template_name] = {
                    "template_type": template_type,
                    "severity": severity
                }

    return {
        "mitre_techniques": mitre_techniques,
        "detection_rules": detection_rules,
        "detection_templates": detection_templates
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
            "case_id",
            "analyst",
            "alert_source",
            "hostname",
            "username",
            "analyst_notes",
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
            "mitre_attack",
            "detection_rules",
            "detection_templates"
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

            detection_rule_values = []

            for rule in result.get("detection_rules", []):
                detection_rule_values.append(
                    f"{rule.get('rule_name')} ({rule.get('severity')})"
                )

            case_context = result.get("case_context", {})

            detection_template_values = []

            for template in result.get("detection_templates", []):
                detection_template_values.append(
                    f"{template.get('template_name')} ({template.get('template_type')} - {template.get('severity')})"
                )

            writer.writerow({
                "timestamp": result.get("timestamp", ""),
                "case_id": case_context.get("case_id", ""),
                "analyst": case_context.get("analyst", ""),
                "alert_source": case_context.get("alert_source", ""),
                "hostname": case_context.get("hostname", ""),
                "username": case_context.get("username", ""),
                "analyst_notes": case_context.get("analyst_notes", ""),
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
                "mitre_attack": " | ".join(mitre_values),
                "detection_rules": " | ".join(detection_rule_values),
                "detection_templates": " | ".join(detection_template_values)
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
        report_branding = {}

        for result in analysis_results:
            if result.get("report_branding"):
                report_branding = result.get("report_branding", {})
                break

        report_title = report_branding.get(
            "report_title",
            "Encoded Command Analyzer Triage Report"
        )

        file.write(f"# {report_title}\n\n")

        if report_branding.get("organization"):
            file.write(f"**Organization:** {report_branding.get('organization')}\n\n")

        if report_branding.get("classification"):
            file.write(f"**Classification:** {report_branding.get('classification')}\n\n")

        file.write("---\n\n")

        file.write("## Summary\n\n")
        file.write(f"- Total Results: {len(analysis_results)}\n")
        file.write(f"- Highest Risk: {highest_risk}\n")
        file.write(f"- Highest Score: {highest_score}\n\n")
        
        case_context = {}

        for result in analysis_results:
            if result.get("case_context"):
                case_context = result.get("case_context", {})
                break

        if case_context:
            file.write("## Case Context\n\n")
            file.write(f"- Case ID: {case_context.get('case_id', '')}\n")
            file.write(f"- Analyst: {case_context.get('analyst', '')}\n")
            file.write(f"- Alert Source: {case_context.get('alert_source', '')}\n")
            file.write(f"- Hostname: {case_context.get('hostname', '')}\n")
            file.write(f"- Username: {case_context.get('username', '')}\n")
            file.write(f"- Analyst Notes: {case_context.get('analyst_notes', '')}\n\n")

        file.write("---\n\n")
        
        coverage_summary = build_detection_coverage_summary(analysis_results)

        file.write("## Detection Coverage Summary\n\n")

        file.write("### MITRE Techniques Covered\n\n")
        if coverage_summary["mitre_techniques"]:
            for technique_id, details in coverage_summary["mitre_techniques"].items():
                file.write(
                    f"- {technique_id} - {details.get('technique_name')} "
                    f"({details.get('tactic')})\n"
                )
        else:
            file.write("- No MITRE techniques identified.\n")

        file.write("\n### Detection Rule Ideas\n\n")
        if coverage_summary["detection_rules"]:
            for rule_name, severity in coverage_summary["detection_rules"].items():
                file.write(f"- {rule_name} ({severity})\n")
        else:
            file.write("- No detection rule ideas identified.\n")

        file.write("\n### Detection Templates\n\n")
        if coverage_summary["detection_templates"]:
            for template_name, details in coverage_summary["detection_templates"].items():
                file.write(
                    f"- {details.get('template_type')}: {template_name} "
                    f"({details.get('severity')})\n"
                )
        else:
            file.write("- No detection templates identified.\n")

        file.write("\n---\n\n")

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

            file.write("\n")

            file.write("### Detection Rule Mapping\n\n")

            detection_rules = result.get("detection_rules", [])

            if detection_rules:
                for rule in detection_rules:
                    file.write(f"- {rule.get('rule_name')}\n")
                    file.write(f"  - Severity: {rule.get('severity')}\n")
                    file.write(f"  - Description: {rule.get('description')}\n")
                    file.write(f"  - Log Sources: {', '.join(rule.get('log_sources', []))}\n")
                    file.write(f"  - Reason: {rule.get('reason')}\n")
            else:
                file.write("- No detection rule mappings identified.\n")
                
            file.write("\n")

            file.write("### Detection Templates\n\n")

            detection_templates = result.get("detection_templates", [])

            if detection_templates:
                for template in detection_templates:
                    file.write(f"- {template.get('template_name')}\n")
                    file.write(f"  - Type: {template.get('template_type')}\n")
                    file.write(f"  - Severity: {template.get('severity')}\n")
                    file.write(f"  - Description: {template.get('description')}\n")
                    file.write("  - Query:\n\n")
                    file.write("```text\n")
                    file.write(f"{template.get('query', '')}\n")
                    file.write("```\n\n")
            else:
                file.write("- No detection templates identified.\n")

            file.write("\n---\n\n")
        
    return file_path
    
def export_to_html(analysis_results):
    os.makedirs("output", exist_ok=True)

    file_path = "output/triage_report.html"

    highest_score = 0
    highest_risk = "None"

    for result in analysis_results:
        score = result.get("risk_score", 0)

        if score > highest_score:
            highest_score = score
            highest_risk = result.get("risk_level", "None")

    def escape_html(value):
        return (
            str(value)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )

    with open(file_path, "w", encoding="utf-8") as file:
        file.write("""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Encoded Command Analyzer Triage Report</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #0f172a;
            color: #e5e7eb;
            margin: 0;
            padding: 30px;
        }

        .container {
            max-width: 1200px;
            margin: auto;
        }

        h1 {
            color: #ffffff;
            border-bottom: 2px solid #334155;
            padding-bottom: 10px;
        }

        h2 {
            color: #93c5fd;
            margin-top: 30px;
        }

        h3 {
            color: #c4b5fd;
            margin-top: 20px;
        }

        .summary {
            background-color: #1e293b;
            border: 1px solid #334155;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 25px;
        }

        .finding {
            background-color: #1e293b;
            border: 1px solid #334155;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 25px;
        }

        .risk-high {
            color: #fecaca;
            background-color: #7f1d1d;
            padding: 6px 10px;
            border-radius: 6px;
            font-weight: bold;
        }

        .risk-medium {
            color: #fed7aa;
            background-color: #7c2d12;
            padding: 6px 10px;
            border-radius: 6px;
            font-weight: bold;
        }

        .risk-low {
            color: #fef3c7;
            background-color: #713f12;
            padding: 6px 10px;
            border-radius: 6px;
            font-weight: bold;
        }

        .risk-none {
            color: #bbf7d0;
            background-color: #14532d;
            padding: 6px 10px;
            border-radius: 6px;
            font-weight: bold;
        }

        pre {
            background-color: #020617;
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 12px;
            overflow-x: auto;
            color: #d1d5db;
        }

        ul {
            line-height: 1.6;
        }

        .metadata {
            color: #cbd5e1;
        }

        .section {
            margin-top: 18px;
        }

        .rule-card {
            background-color: #0f172a;
            border: 1px solid #475569;
            border-radius: 8px;
            padding: 12px;
            margin-bottom: 10px;
        }

        .muted {
            color: #94a3b8;
        }
    </style>
</head>
<body>
<div class="container">
""")

        report_branding = {}

        for result in analysis_results:
            if result.get("report_branding"):
                report_branding = result.get("report_branding", {})
                break

        report_title = report_branding.get(
            "report_title",
            "Encoded Command Analyzer Triage Report"
        )

        file.write(f"<h1>{escape_html(report_title)}</h1>\n")

        if report_branding.get("organization") or report_branding.get("classification"):
            file.write('<div class="summary">\n')
            file.write("<h2>Report Information</h2>\n")

            if report_branding.get("organization"):
                file.write(
                    f"<p><strong>Organization:</strong> "
                    f"{escape_html(report_branding.get('organization'))}</p>\n"
                )

            if report_branding.get("classification"):
                file.write(
                    f"<p><strong>Classification:</strong> "
                    f"{escape_html(report_branding.get('classification'))}</p>\n"
                )

            file.write("</div>\n")

        risk_class = f"risk-{highest_risk.lower()}"

        file.write('<div class="summary">\n')
        file.write("<h2>Summary</h2>\n")
        file.write(f"<p><strong>Total Results:</strong> {len(analysis_results)}</p>\n")
        file.write(f'<p><strong>Highest Risk:</strong> <span class="{risk_class}">{escape_html(highest_risk)}</span></p>\n')
        file.write(f"<p><strong>Highest Score:</strong> {highest_score}</p>\n")
        file.write("</div>\n")
        
        case_context = {}

        for result in analysis_results:
            if result.get("case_context"):
                case_context = result.get("case_context", {})
                break

        if case_context:
            file.write('<div class="summary">\n')
            file.write("<h2>Case Context</h2>\n")
            file.write("<ul>\n")
            file.write(f"<li><strong>Case ID:</strong> {escape_html(case_context.get('case_id', ''))}</li>\n")
            file.write(f"<li><strong>Analyst:</strong> {escape_html(case_context.get('analyst', ''))}</li>\n")
            file.write(f"<li><strong>Alert Source:</strong> {escape_html(case_context.get('alert_source', ''))}</li>\n")
            file.write(f"<li><strong>Hostname:</strong> {escape_html(case_context.get('hostname', ''))}</li>\n")
            file.write(f"<li><strong>Username:</strong> {escape_html(case_context.get('username', ''))}</li>\n")
            file.write(f"<li><strong>Analyst Notes:</strong> {escape_html(case_context.get('analyst_notes', ''))}</li>\n")
            file.write("</ul>\n")
            file.write("</div>\n")
        
        coverage_summary = build_detection_coverage_summary(analysis_results)

        file.write('<div class="summary">\n')
        file.write("<h2>Detection Coverage Summary</h2>\n")

        file.write("<h3>MITRE Techniques Covered</h3>\n")
        if coverage_summary["mitre_techniques"]:
            file.write("<ul>\n")
            for technique_id, details in coverage_summary["mitre_techniques"].items():
                file.write(
                    f"<li><strong>{escape_html(technique_id)} - "
                    f"{escape_html(details.get('technique_name'))}</strong> "
                    f"({escape_html(details.get('tactic'))})</li>\n"
                )
            file.write("</ul>\n")
        else:
            file.write('<p class="muted">No MITRE techniques identified.</p>\n')

        file.write("<h3>Detection Rule Ideas</h3>\n")
        if coverage_summary["detection_rules"]:
            file.write("<ul>\n")
            for rule_name, severity in coverage_summary["detection_rules"].items():
                file.write(
                    f"<li>{escape_html(rule_name)} "
                    f"({escape_html(severity)})</li>\n"
                )
            file.write("</ul>\n")
        else:
            file.write('<p class="muted">No detection rule ideas identified.</p>\n')

        file.write("<h3>Detection Templates</h3>\n")
        if coverage_summary["detection_templates"]:
            file.write("<ul>\n")
            for template_name, details in coverage_summary["detection_templates"].items():
                file.write(
                    f"<li>{escape_html(details.get('template_type'))}: "
                    f"{escape_html(template_name)} "
                    f"({escape_html(details.get('severity'))})</li>\n"
                )
            file.write("</ul>\n")
        else:
            file.write('<p class="muted">No detection templates identified.</p>\n')

        file.write("</div>\n")

        for index, result in enumerate(analysis_results, start=1):
            risk_level = result.get("risk_level", "None")
            risk_class = f"risk-{risk_level.lower()}"

            file.write('<div class="finding">\n')
            file.write(f"<h2>Finding {index}</h2>\n")

            file.write('<div class="section metadata">\n')
            file.write("<h3>Metadata</h3>\n")
            file.write("<ul>\n")
            file.write(f"<li><strong>Timestamp:</strong> {escape_html(result.get('timestamp', ''))}</li>\n")
            file.write(f"<li><strong>Encoding:</strong> {escape_html(result.get('encoding', ''))}</li>\n")
            file.write(f"<li><strong>Decode Level:</strong> {escape_html(result.get('decode_level', ''))}</li>\n")
            file.write(f"<li><strong>Source Encoding:</strong> {escape_html(result.get('source_encoding', ''))}</li>\n")
            file.write(f"<li><strong>Batch Item:</strong> {escape_html(result.get('batch_item', ''))}</li>\n")
            file.write(f"<li><strong>Source File:</strong> {escape_html(result.get('source_file', ''))}</li>\n")
            file.write("</ul>\n")
            file.write("</div>\n")

            file.write('<div class="section">\n')
            file.write("<h3>Original Input</h3>\n")
            file.write(f"<pre>{escape_html(result.get('original_input', ''))}</pre>\n")
            file.write("</div>\n")

            file.write('<div class="section">\n')
            file.write("<h3>Decoded Output</h3>\n")
            file.write(f"<pre>{escape_html(result.get('decoded_text', ''))}</pre>\n")
            file.write("</div>\n")

            file.write('<div class="section">\n')
            file.write("<h3>Suspicious Keywords</h3>\n")
            suspicious_keywords = result.get("suspicious_keywords", [])

            if suspicious_keywords:
                file.write("<ul>\n")
                for keyword in suspicious_keywords:
                    file.write(f"<li>{escape_html(keyword)}</li>\n")
                file.write("</ul>\n")
            else:
                file.write('<p class="muted">No suspicious keywords found.</p>\n')
            file.write("</div>\n")

            file.write('<div class="section">\n')
            file.write("<h3>Risk Score</h3>\n")
            file.write(f'<p><strong>Risk Level:</strong> <span class="{risk_class}">{escape_html(risk_level)}</span></p>\n')
            file.write(f"<p><strong>Score:</strong> {escape_html(result.get('risk_score', 0))}</p>\n")
            file.write("</div>\n")

            file.write('<div class="section">\n')
            file.write("<h3>Risk Reasons</h3>\n")
            reasons = result.get("reasons", [])

            if reasons:
                file.write("<ul>\n")
                for reason in reasons:
                    file.write(f"<li>{escape_html(reason)}</li>\n")
                file.write("</ul>\n")
            else:
                file.write('<p class="muted">No risk reasons generated.</p>\n')
            file.write("</div>\n")

            file.write('<div class="section">\n')
            file.write("<h3>MITRE ATT&CK Mapping</h3>\n")
            mitre_attack = result.get("mitre_attack", [])

            if mitre_attack:
                file.write("<ul>\n")
                for technique in mitre_attack:
                    file.write(
                        f"<li><strong>{escape_html(technique.get('technique_id'))} - "
                        f"{escape_html(technique.get('technique_name'))}</strong> "
                        f"({escape_html(technique.get('tactic'))})<br>"
                        f"<span class='muted'>Reason: {escape_html(technique.get('reason'))}</span></li>\n"
                    )
                file.write("</ul>\n")
            else:
                file.write('<p class="muted">No MITRE ATT&CK mappings identified.</p>\n')
            file.write("</div>\n")

            file.write('<div class="section">\n')
            file.write("<h3>Detection Rule Mapping</h3>\n")
            detection_rules = result.get("detection_rules", [])

            if detection_rules:
                for rule in detection_rules:
                    file.write('<div class="rule-card">\n')
                    file.write(f"<strong>{escape_html(rule.get('rule_name'))}</strong><br>\n")
                    file.write(f"<span class='muted'>Severity:</span> {escape_html(rule.get('severity'))}<br>\n")
                    file.write(f"<span class='muted'>Description:</span> {escape_html(rule.get('description'))}<br>\n")
                    file.write(f"<span class='muted'>Log Sources:</span> {escape_html(', '.join(rule.get('log_sources', [])))}<br>\n")
                    file.write(f"<span class='muted'>Reason:</span> {escape_html(rule.get('reason'))}\n")
                    file.write("</div>\n")
            else:
                file.write('<p class="muted">No detection rule mappings identified.</p>\n')
            file.write("</div>\n")
            
            file.write('<div class="section">\n')
            file.write("<h3>Detection Templates</h3>\n")
            detection_templates = result.get("detection_templates", [])

            if detection_templates:
                for template in detection_templates:
                    file.write('<div class="rule-card">\n')
                    file.write(f"<strong>{escape_html(template.get('template_name'))}</strong><br>\n")
                    file.write(f"<span class='muted'>Type:</span> {escape_html(template.get('template_type'))}<br>\n")
                    file.write(f"<span class='muted'>Severity:</span> {escape_html(template.get('severity'))}<br>\n")
                    file.write(f"<span class='muted'>Description:</span> {escape_html(template.get('description'))}<br>\n")
                    file.write("<span class='muted'>Query:</span>\n")
                    file.write(f"<pre>{escape_html(template.get('query', ''))}</pre>\n")
                    file.write("</div>\n")
            else:
                file.write('<p class="muted">No detection templates identified.</p>\n')

            file.write("</div>\n")

            file.write("</div>\n")

        file.write("""
</div>
</body>
</html>
""")

    return file_path