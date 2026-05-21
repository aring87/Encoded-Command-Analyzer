import os
import yaml


def load_yaml_detection_templates(template_root="templates"):
    """
    Loads detection templates from YAML files under the templates directory.

    Expected structure:
        templates/
        ├── sigma/
        │   └── rule.yml
        └── sentinel/
            └── rule.yml
    """

    templates = []

    if not os.path.exists(template_root):
        return templates

    for root, _, files in os.walk(template_root):
        for file_name in files:
            if not file_name.lower().endswith((".yml", ".yaml")):
                continue

            file_path = os.path.join(root, file_name)

            try:
                with open(file_path, "r", encoding="utf-8") as template_file:
                    template_data = yaml.safe_load(template_file)

                if not isinstance(template_data, dict):
                    continue

                template_data["source_file"] = file_path
                templates.append(template_data)

            except Exception as error:
                print(f"[!] Failed to load template {file_path}: {error}")

    return templates


def match_yaml_detection_templates(decoded_text, template_root="templates"):
    """
    Matches decoded content against YAML detection templates using keyword matching.
    """

    matched_templates = []
    decoded_text_lower = decoded_text.lower()

    templates = load_yaml_detection_templates(template_root)

    for template in templates:
        keywords = template.get("keywords", [])

        for keyword in keywords:
            if str(keyword).lower() in decoded_text_lower:
                matched_templates.append(template)
                break

    return matched_templates