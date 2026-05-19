import base64
import gzip
import unittest

from decoder_engine import decode_input


class TestDecoderEngine(unittest.TestCase):

    def test_utf8_base64_decode(self):
        results = decode_input("SGVsbG8gd29ybGQ=")

        decoded_values = [result["decoded_text"] for result in results]

        self.assertIn("Hello world", decoded_values)

    def test_powershell_utf16le_decode(self):
        results = decode_input("cABvAHcAZQByAHMAaABlAGwAbAAuAGUAeABlACAALQBlAG4AYwAgAEkARQBYAA==")

        decoded_values = [result["decoded_text"] for result in results]

        self.assertIn("powershell.exe -enc IEX", decoded_values)

    def test_url_decode(self):
        results = decode_input("powershell%2Eexe%20-enc%20IEX")

        decoded_values = [result["decoded_text"] for result in results]

        self.assertIn("powershell.exe -enc IEX", decoded_values)

    def test_hex_decode(self):
        results = decode_input("706f7765727368656c6c2e657865202d656e6320494558")

        decoded_values = [result["decoded_text"] for result in results]

        self.assertIn("powershell.exe -enc IEX", decoded_values)

    def test_chained_base64_url_decode(self):
        results = decode_input("cG93ZXJzaGVsbCUyRWV4ZSUyMC1lbmMlMjBJRVg=")

        decoded_values = [result["decoded_text"] for result in results]

        self.assertIn("powershell%2Eexe%20-enc%20IEX", decoded_values)
        self.assertIn("powershell.exe -enc IEX", decoded_values)

    def test_gzip_base64_decode(self):
        test_text = "powershell.exe -enc IEX"

        compressed = gzip.compress(test_text.encode("utf-8"))
        encoded = base64.b64encode(compressed).decode("utf-8")

        results = decode_input(encoded)

        decoded_values = [result["decoded_text"] for result in results]

        self.assertIn(test_text, decoded_values)

    def test_xor_hex_decode(self):
        results = decode_input("534c544651504b464f4f0d465b46030e464d40036a667b")

        decoded_values = [result["decoded_text"] for result in results]

        self.assertIn("powershell.exe -enc IEX", decoded_values)


if __name__ == "__main__":
    unittest.main()