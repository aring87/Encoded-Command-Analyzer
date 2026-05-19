import base64
from urllib.parse import unquote

def decode_base64(encoded_text):
    try:
        decoded_bytes = base64.b64decode(encoded_text)

        decoded_results = []

        try:
            utf16_text = decoded_bytes.decode("utf-16le")

            if any(keyword in utf16_text.lower() for keyword in ["powershell", "-enc", "iex", "cmd", "http"]):
                decoded_results.append({
                    "encoding": "UTF-16LE",
                    "decoded_text": utf16_text
                })
                return decoded_results

        except UnicodeDecodeError:
            pass

        try:
            utf8_text = decoded_bytes.decode("utf-8")

            if "\x00" not in utf8_text:
                decoded_results.append({
                    "encoding": "UTF-8",
                    "decoded_text": utf8_text
                })

        except UnicodeDecodeError:
            pass

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

def decode_url(encoded_text):
    try:
        decoded_text = unquote(encoded_text)
        
        if decoded_text != encoded_text:
            return [{
                "encoding": "URL",
                "decoded_text": decoded_text
            }]
        
        return []
        
    except Exception as error:
        return [{
            "encoding": "Error",
            "decoded_text": f"Error decoding URL encoding: {error}"
        }]

def decode_input(encoded_text):
    decoded_results = []

    base64_results = decode_base64(encoded_text)

    for result in base64_results:
        if result["encoding"] != "Error":
            decoded_results.append(result)

    url_results = decode_url(encoded_text)

    for result in url_results:
        if result["encoding"] != "Error":
            decoded_results.append(result)

    if not decoded_results:
        decoded_results.append({
            "encoding": "Unknown",
            "decoded_text": "Unable to decode input as Base64, PowerShell UTF-16LE, or URL encoding."
        })

    return decoded_results