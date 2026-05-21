import json
import os


DEFAULT_ANALYST_PROFILE = {
    "analyst": "",
    "organization": "",
    "classification": "",
    "default_report_title": "Encoded Command Analyzer Triage Report"
}


def load_analyst_profile(profile_path="config/analyst_profile.json"):
    """
    Loads default analyst/report profile settings from config/analyst_profile.json.

    If the file is missing, empty, or invalid, safe defaults are returned.
    """

    if not os.path.exists(profile_path):
        return DEFAULT_ANALYST_PROFILE.copy()

    try:
        with open(profile_path, "r", encoding="utf-8") as profile_file:
            profile = json.load(profile_file)

        if not isinstance(profile, dict):
            return DEFAULT_ANALYST_PROFILE.copy()

        loaded_profile = DEFAULT_ANALYST_PROFILE.copy()
        loaded_profile.update(profile)

        return loaded_profile

    except Exception as error:
        print(f"[!] Failed to load analyst profile: {error}")
        return DEFAULT_ANALYST_PROFILE.copy()