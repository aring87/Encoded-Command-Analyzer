import unittest

from detection_engine import (
    analyze_decoded_result,
    calculate_risk_score,
    check_suspicious_keywords,
    map_mitre_attack
)


class TestDetectionEngine(unittest.TestCase):

    def test_suspicious_keyword_detection(self):
        decoded_text = "powershell.exe -enc IEX"

        keywords = check_suspicious_keywords(decoded_text)

        self.assertIn("powershell", keywords)
        self.assertIn("-enc", keywords)
        self.assertIn("iex", keywords)

    def test_risk_score_high(self):
        found_keywords = ["powershell", "-enc", "iex"]

        risk_level, score, reasons = calculate_risk_score(found_keywords)

        self.assertEqual(risk_level, "High")
        self.assertEqual(score, 7)
        self.assertGreater(len(reasons), 0)

    def test_mitre_mapping(self):
        found_keywords = ["powershell", "-enc", "iex"]

        mappings = map_mitre_attack(found_keywords)

        technique_ids = [mapping["technique_id"] for mapping in mappings]

        self.assertIn("T1059.001", technique_ids)
        self.assertIn("T1027", technique_ids)

    def test_full_analysis_result(self):
        result = {
            "encoding": "UTF-8",
            "decode_level": 1,
            "decoded_text": "powershell.exe -enc IEX"
        }

        analysis = analyze_decoded_result(result)

        self.assertEqual(analysis["risk_level"], "High")
        self.assertEqual(analysis["risk_score"], 7)
        self.assertIn("mitre_attack", analysis)
        self.assertGreater(len(analysis["mitre_attack"]), 0)


if __name__ == "__main__":
    unittest.main()