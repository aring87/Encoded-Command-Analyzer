import csv
import json
import os
from html import escape


def build_detection_coverage_summary(analysis_results):
    """
    Builds a summary of MITRE techniques, detection rule ideas,
    and detection templates across all analysis results.
    """

    coverage_summary = {
        "mitre_techniques": {},
        "detection_rules": {},
        "detection_templates": {}
    }

    for result in analysis_results:
        for technique in result.get("mitre_attack", []):
            technique_id = technique.get("technique_id", "")

            if technique_id:
                coverage_summary["mitre_techniques"][technique_id] = {
                    "technique_name": technique.get("technique_name", ""),
                    "tactic": technique.get("tactic", "")
                }

        for rule in result.get("detection_rules", []):
            rule_name = rule.get("rule_name", "")

            if rule_name:
                coverage_summary["detection_rules"][rule_name] = rule.get("severity", "")

        for template in result.get("detection_templates", []):
            template_name = template.get("template_name", "")

            if template_name:
                coverage_summary["detection_templates"][template_name] = {
                    "template_type": template.get("template_type", ""),
                    "severity": template.get("severity", "")
                }

    return coverage_summary


def get_highest_risk_summary(analysis_results):
    """
    Returns the highest risk level and highest score across all analysis results.
    """

    highest_score = 0
    highest_risk = "None"

    for result in analysis_results:
        score = result.get("risk_score", 0)

        if score > highest_score:
            highest_score = score
            highest_risk = result.get("risk_level", "None")

    return highest_risk, highest_score


def get_report_branding(analysis_results):
    """
    Gets report branding from the first result that contains it.
    """

    for result in analysis_results:
        if result.get("report_branding"):
            return result.get("report_branding", {})

    return {}


def get_case_context(analysis_results):
    """
    Gets case context from the first result that contains it.
    """

    for result in analysis_results:
        if result.get("case_context"):
            return result.get("case_context", {})

    return {}


def get_visible_case_context(case_context):
    """
    Returns only case context fields that have values.
    This prevents blank fields from appearing in Markdown and HTML reports.
    """

    case_context_fields = {
        "Case ID": case_context.get("case_id", ""),
        "Analyst": case_context.get("analyst", ""),
        "Alert Source": case_context.get("alert_source", ""),
        "Hostname": case_context.get("hostname", ""),
        "Username": case_context.get("username", ""),
        "Analyst Notes": case_context.get("notes", "") or case_context.get("analyst_notes", "")
    }

    visible_case_context = {
        label: value
        for label, value in case_context_fields.items()
        if value
    }

    return visible_case_context


def export_to_json(analysis_results):
    """
    Exports full analysis results to JSON.
    """

    os.makedirs("output", exist_ok=True)

    file_path = "output/analysis_result.json"

    with open(file_path, "w", encoding="utf-8") as file:
        json.dump(analysis_results, file, indent=4)

    return file_path


def export_to_csv(analysis_results):
    """
    Exports flattened analysis results to CSV.
    """

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

            detection_template_values = []

            for template in result.get("detection_templates", []):
                detection_template_values.append(
                    f"{template.get('template_name')} "
                    f"({template.get('template_type')} - {template.get('severity')})"
                )

            case_context = result.get("case_context", {})

            writer.writerow({
                "timestamp": result.get("timestamp", ""),
                "case_id": case_context.get("case_id", ""),
                "analyst": case_context.get("analyst", ""),
                "alert_source": case_context.get("alert_source", ""),
                "hostname": case_context.get("hostname", ""),
                "username": case_context.get("username", ""),
                "analyst_notes": case_context.get("notes", "") or case_context.get("analyst_notes", ""),
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
    """
    Exports analyst-friendly triage report to Markdown.
    Blank case context fields are automatically removed.
    """

    os.makedirs("output", exist_ok=True)

    file_path = "output/triage_report.md"

    highest_risk, highest_score = get_highest_risk_summary(analysis_results)
    report_branding = get_report_branding(analysis_results)
    case_context = get_case_context(analysis_results)
    visible_case_context = get_visible_case_context(case_context)
    coverage_summary = build_detection_coverage_summary(analysis_results)

    report_title = report_branding.get(
        "report_title",
        "Encoded Command Analyzer Triage Report"
    )

    with open(file_path, "w", encoding="utf-8") as file:
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

        if visible_case_context:
            file.write("## Case Context\n\n")

            for label, value in visible_case_context.items():
                file.write(f"- {label}: {value}\n")

            file.write("\n")

        file.write("---\n\n")

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
    """
    Exports analyst-friendly triage report to HTML.
    Blank case context fields are automatically removed.
    """

    os.makedirs("output", exist_ok=True)

    file_path = "output/triage_report.html"

    highest_risk, highest_score = get_highest_risk_summary(analysis_results)
    report_branding = get_report_branding(analysis_results)
    case_context = get_case_context(analysis_results)
    visible_case_context = get_visible_case_context(case_context)
    coverage_summary = build_detection_coverage_summary(analysis_results)

    report_title = report_branding.get(
        "report_title",
        "Encoded Command Analyzer Triage Report"
    )

    organization = report_branding.get("organization", "")
    classification = report_branding.get("classification", "")

    html_parts = []

    html_parts.append("<!DOCTYPE html>")
    html_parts.append("<html lang='en'>")
    html_parts.append("<head>")
    html_parts.append("<meta charset='UTF-8'>")
    html_parts.append("<meta name='viewport' content='width=device-width, initial-scale=1.0'>")
    html_parts.append(f"<title>{escape(report_title)}</title>")
    html_parts.append("""
<style>
body {
    background-color: #0f172a;
    color: #e5e7eb;
    font-family: Arial, sans-serif;
    margin: 0;
    padding: 0;
}
.container {
    max-width: 1100px;
    margin: 0 auto;
    padding: 32px;
}
.header {
    background-color: #111827;
    border: 1px solid #334155;
    border-radius: 12px;
    padding: 24px;
    margin-bottom: 24px;
}
.card {
    background-color: #111827;
    border: 1px solid #334155;
    border-radius: 12px;
    padding: 20px;
    margin-bottom: 24px;
}
h1, h2, h3 {
    color: #f8fafc;
}
.meta {
    color: #cbd5e1;
}
.badge {
    display: inline-block;
    background-color: #1e293b;
    border: 1px solid #475569;
    border-radius: 999px;
    padding: 6px 10px;
    margin: 4px 4px 4px 0;
}
pre {
    background-color: #020617;
    color: #e5e7eb;
    border: 1px solid #334155;
    border-radius: 8px;
    padding: 14px;
    overflow-x: auto;
}
code {
    white-space: pre-wrap;
}
ul {
    line-height: 1.7;
}
hr {
    border: none;
    border-top: 1px solid #334155;
    margin: 24px 0;
}
.risk-high {
    color: #f87171;
    font-weight: bold;
}
.risk-medium {
    color: #fbbf24;
    font-weight: bold;
}
.risk-low {
    color: #60a5fa;
    font-weight: bold;
}
.risk-none {
    color: #34d399;
    font-weight: bold;
}
</style>
""")
    html_parts.append("</head>")
    html_parts.append("<body>")
    html_parts.append("<div class='container'>")

    html_parts.append("<div class='header'>")
    html_parts.append(f"<h1>{escape(report_title)}</h1>")

    if organization:
        html_parts.append(f"<p><strong>Organization:</strong> {escape(organization)}</p>")

    if classification:
        html_parts.append(f"<p><strong>Classification:</strong> {escape(classification)}</p>")

    html_parts.append("</div>")

    html_parts.append("<div class='card'>")
    html_parts.append("<h2>Summary</h2>")
    html_parts.append("<ul>")
    html_parts.append(f"<li><strong>Total Results:</strong> {len(analysis_results)}</li>")
    html_parts.append(f"<li><strong>Highest Risk:</strong> {escape(str(highest_risk))}</li>")
    html_parts.append(f"<li><strong>Highest Score:</strong> {escape(str(highest_score))}</li>")
    html_parts.append("</ul>")
    html_parts.append("</div>")

    if visible_case_context:
        html_parts.append("<div class='card'>")
        html_parts.append("<h2>Case Context</h2>")
        html_parts.append("<ul>")

        for label, value in visible_case_context.items():
            html_parts.append(
                f"<li><strong>{escape(label)}:</strong> {escape(str(value))}</li>"
            )

        html_parts.append("</ul>")
        html_parts.append("</div>")

    html_parts.append("<div class='card'>")
    html_parts.append("<h2>Detection Coverage Summary</h2>")

    html_parts.append("<h3>MITRE Techniques Covered</h3>")
    html_parts.append("<ul>")
    if coverage_summary["mitre_techniques"]:
        for technique_id, details in coverage_summary["mitre_techniques"].items():
            html_parts.append(
                f"<li>{escape(technique_id)} - "
                f"{escape(str(details.get('technique_name', '')))} "
                f"({escape(str(details.get('tactic', '')))})</li>"
            )
    else:
        html_parts.append("<li>No MITRE techniques identified.</li>")
    html_parts.append("</ul>")

    html_parts.append("<h3>Detection Rule Ideas</h3>")
    html_parts.append("<ul>")
    if coverage_summary["detection_rules"]:
        for rule_name, severity in coverage_summary["detection_rules"].items():
            html_parts.append(
                f"<li>{escape(rule_name)} ({escape(str(severity))})</li>"
            )
    else:
        html_parts.append("<li>No detection rule ideas identified.</li>")
    html_parts.append("</ul>")

    html_parts.append("<h3>Detection Templates</h3>")
    html_parts.append("<ul>")
    if coverage_summary["detection_templates"]:
        for template_name, details in coverage_summary["detection_templates"].items():
            html_parts.append(
                f"<li>{escape(str(details.get('template_type', '')))}: "
                f"{escape(template_name)} "
                f"({escape(str(details.get('severity', '')))})</li>"
            )
    else:
        html_parts.append("<li>No detection templates identified.</li>")
    html_parts.append("</ul>")

    html_parts.append("</div>")

    for index, result in enumerate(analysis_results, start=1):
        risk_level = result.get("risk_level", "None")
        risk_class = f"risk-{str(risk_level).lower()}"

        html_parts.append("<div class='card'>")
        html_parts.append(f"<h2>Finding {index}</h2>")

        html_parts.append("<h3>Metadata</h3>")
        html_parts.append("<ul>")
        html_parts.append(f"<li><strong>Timestamp:</strong> {escape(str(result.get('timestamp', '')))}</li>")
        html_parts.append(f"<li><strong>Encoding:</strong> {escape(str(result.get('encoding', '')))}</li>")
        html_parts.append(f"<li><strong>Decode Level:</strong> {escape(str(result.get('decode_level', '')))}</li>")

        if result.get("source_encoding"):
            html_parts.append(
                f"<li><strong>Source Encoding:</strong> {escape(str(result.get('source_encoding', '')))}</li>"
            )

        if result.get("batch_item"):
            html_parts.append(
                f"<li><strong>Batch Item:</strong> {escape(str(result.get('batch_item', '')))}</li>"
            )

        if result.get("source_file"):
            html_parts.append(
                f"<li><strong>Source File:</strong> {escape(str(result.get('source_file', '')))}</li>"
            )

        html_parts.append("</ul>")

        html_parts.append("<h3>Original Input</h3>")
        html_parts.append("<pre><code>")
        html_parts.append(escape(str(result.get("original_input", ""))))
        html_parts.append("</code></pre>")

        html_parts.append("<h3>Decoded Output</h3>")
        html_parts.append("<pre><code>")
        html_parts.append(escape(str(result.get("decoded_text", ""))))
        html_parts.append("</code></pre>")

        html_parts.append("<h3>Suspicious Keywords</h3>")
        suspicious_keywords = result.get("suspicious_keywords", [])
        html_parts.append("<ul>")
        if suspicious_keywords:
            for keyword in suspicious_keywords:
                html_parts.append(f"<li>{escape(str(keyword))}</li>")
        else:
            html_parts.append("<li>None</li>")
        html_parts.append("</ul>")

        html_parts.append("<h3>Risk Score</h3>")
        html_parts.append("<ul>")
        html_parts.append(
            f"<li><strong>Risk Level:</strong> "
            f"<span class='{escape(risk_class)}'>{escape(str(risk_level))}</span></li>"
        )
        html_parts.append(f"<li><strong>Score:</strong> {escape(str(result.get('risk_score', 0)))}</li>")
        html_parts.append("</ul>")

        html_parts.append("<h3>Risk Reasons</h3>")
        reasons = result.get("reasons", [])
        html_parts.append("<ul>")
        if reasons:
            for reason in reasons:
                html_parts.append(f"<li>{escape(str(reason))}</li>")
        else:
            html_parts.append("<li>No risk reasons generated.</li>")
        html_parts.append("</ul>")

        html_parts.append("<h3>MITRE ATT&CK Mapping</h3>")
        mitre_attack = result.get("mitre_attack", [])
        html_parts.append("<ul>")
        if mitre_attack:
            for technique in mitre_attack:
                html_parts.append(
                    f"<li><strong>{escape(str(technique.get('technique_id', '')))} - "
                    f"{escape(str(technique.get('technique_name', '')))}</strong> "
                    f"({escape(str(technique.get('tactic', '')))})"
                )

                if technique.get("reason"):
                    html_parts.append(
                        f"<br><span class='meta'>Reason: {escape(str(technique.get('reason')))}</span>"
                    )

                html_parts.append("</li>")
        else:
            html_parts.append("<li>No MITRE ATT&CK mappings identified.</li>")
        html_parts.append("</ul>")

        html_parts.append("<h3>Detection Rule Mapping</h3>")
        detection_rules = result.get("detection_rules", [])
        html_parts.append("<ul>")
        if detection_rules:
            for rule in detection_rules:
                html_parts.append("<li>")
                html_parts.append(f"<strong>{escape(str(rule.get('rule_name', '')))}</strong><br>")
                html_parts.append(f"<span class='meta'>Severity: {escape(str(rule.get('severity', '')))}</span><br>")
                html_parts.append(f"<span class='meta'>Description: {escape(str(rule.get('description', '')))}</span><br>")

                log_sources = rule.get("log_sources", [])
                if log_sources:
                    html_parts.append(
                        f"<span class='meta'>Log Sources: {escape(', '.join(log_sources))}</span><br>"
                    )

                if rule.get("reason"):
                    html_parts.append(
                        f"<span class='meta'>Reason: {escape(str(rule.get('reason')))}</span>"
                    )

                html_parts.append("</li>")
        else:
            html_parts.append("<li>No detection rule mappings identified.</li>")
        html_parts.append("</ul>")

        html_parts.append("<h3>Detection Templates</h3>")
        detection_templates = result.get("detection_templates", [])

        if detection_templates:
            for template in detection_templates:
                html_parts.append("<div class='card'>")
                html_parts.append(f"<h3>{escape(str(template.get('template_name', '')))}</h3>")
                html_parts.append("<ul>")
                html_parts.append(f"<li><strong>Type:</strong> {escape(str(template.get('template_type', '')))}</li>")
                html_parts.append(f"<li><strong>Severity:</strong> {escape(str(template.get('severity', '')))}</li>")
                html_parts.append(f"<li><strong>Description:</strong> {escape(str(template.get('description', '')))}</li>")
                html_parts.append("</ul>")
                html_parts.append("<pre><code>")
                html_parts.append(escape(str(template.get("query", ""))))
                html_parts.append("</code></pre>")
                html_parts.append("</div>")
        else:
            html_parts.append("<p>No detection templates identified.</p>")

        html_parts.append("</div>")

    html_parts.append("</div>")
    html_parts.append("</body>")
    html_parts.append("</html>")

    with open(file_path, "w", encoding="utf-8") as file:
        file.write("\n".join(html_parts))

    return file_path


def export_all(analysis_results):
    """
    Exports analysis results to JSON, CSV, Markdown, and HTML.
    """

    json_path = export_to_json(analysis_results)
    csv_path = export_to_csv(analysis_results)
    markdown_path = export_to_markdown(analysis_results)
    html_path = export_to_html(analysis_results)

    return {
        "json": json_path,
        "csv": csv_path,
        "markdown": markdown_path,
        "html": html_path
    }