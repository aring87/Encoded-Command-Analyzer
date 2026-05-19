import base64
import gzip
import zlib
from urllib.parse import unquote


SUSPICIOUS_HINTS = [
    "powershell",
    "-enc",
    "-encodedcommand",
    "iex",
    "cmd",
    "http",
    "https",
    "wscript",
    "cscript"
]


def looks_readable(text):
    if not text or not text.strip():
        return False

    lowered_text = text.lower()

    if any(hint in lowered_text for hint in SUSPICIOUS_HINTS):
        return True

    readable_characters = 0

    for character in text:
        if character.isascii() and (character.isprintable() or character in "\r\n\t"):
            readable_characters += 1

    readable_ratio = readable_characters / len(text)

    return readable_ratio >= 0.85


def decode_base64(encoded_text):
    try:
        cleaned_text = encoded_text.strip()
        decoded_bytes = base64.b64decode(cleaned_text, validate=True)

        decoded_results = []

        try:
            utf16_text = decoded_bytes.decode("utf-16le")

            if looks_readable(utf16_text):
                decoded_results.append({
                    "encoding": "UTF-16LE",
                    "decoded_text": utf16_text
                })

                if any(hint in utf16_text.lower() for hint in SUSPICIOUS_HINTS):
                    return decoded_results

        except UnicodeDecodeError:
            pass

        try:
            utf8_text = decoded_bytes.decode("utf-8")

            if looks_readable(utf8_text):
                decoded_results.append({
                    "encoding": "UTF-8",
                    "decoded_text": utf8_text
                })

        except UnicodeDecodeError:
            pass

        return decoded_results

    except Exception:
        return []

def decode_compressed_base64(encoded_text):
    try:
        cleaned_text = encoded_text.strip()
        decoded_bytes = base64.b64decode(cleaned_text, validate=True)

        decoded_results = []

        # Try Gzip decompression
        try:
            gzip_bytes = gzip.decompress(decoded_bytes)
            gzip_text = gzip_bytes.decode("utf-8", errors="ignore")

            if looks_readable(gzip_text):
                decoded_results.append({
                    "encoding": "Gzip Base64",
                    "decoded_text": gzip_text
                })

        except Exception:
            pass

        # Try zlib/deflate decompression
        try:
            deflate_bytes = zlib.decompress(decoded_bytes)
            deflate_text = deflate_bytes.decode("utf-8", errors="ignore")

            if looks_readable(deflate_text):
                decoded_results.append({
                    "encoding": "Deflate Base64",
                    "decoded_text": deflate_text
                })

        except Exception:
            pass

        # Try raw deflate
        try:
            raw_deflate_bytes = zlib.decompress(decoded_bytes, -zlib.MAX_WBITS)
            raw_deflate_text = raw_deflate_bytes.decode("utf-8", errors="ignore")

            if looks_readable(raw_deflate_text):
                decoded_results.append({
                    "encoding": "Raw Deflate Base64",
                    "decoded_text": raw_deflate_text
                })

        except Exception:
            pass

        return decoded_results

    except Exception:
        return []

def decode_url(encoded_text):
    try:
        decoded_text = unquote(encoded_text.strip())

        if decoded_text != encoded_text and looks_readable(decoded_text):
            return [{
                "encoding": "URL",
                "decoded_text": decoded_text
            }]

        return []

    except Exception:
        return []


def decode_hex(encoded_text):
    try:
        cleaned_text = encoded_text.strip().replace(" ", "").replace("0x", "")

        if len(cleaned_text) % 2 != 0:
            return []

        if not all(character in "0123456789abcdefABCDEF" for character in cleaned_text):
            return []

        decoded_bytes = bytes.fromhex(cleaned_text)
        decoded_text = decoded_bytes.decode("utf-8", errors="ignore")

        lowered_text = decoded_text.lower()

        if any(hint in lowered_text for hint in SUSPICIOUS_HINTS):
            return [{
                "encoding": "Hex",
                "decoded_text": decoded_text
            }]

        return []

    except Exception:
        return []

def decode_xor_hex(encoded_text):
    try:
        cleaned_text = encoded_text.strip().replace(" ", "").replace("0x", "")

        if len(cleaned_text) % 2 != 0:
            return []

        if not all(character in "0123456789abcdefABCDEF" for character in cleaned_text):
            return []

        encoded_bytes = bytes.fromhex(cleaned_text)
        candidates = []

        for key in range(1, 256):
            decoded_bytes = bytes(byte ^ key for byte in encoded_bytes)
            decoded_text = decoded_bytes.decode("utf-8", errors="ignore")
            lowered_text = decoded_text.lower()

            matched_hints = []

            for hint in SUSPICIOUS_HINTS:
                if hint in lowered_text:
                    matched_hints.append(hint)

            if not matched_hints:
                continue

            if not looks_readable(decoded_text):
                continue

            confidence_score = 0

            if "powershell" in lowered_text:
                confidence_score += 5

            if "powershell.exe" in lowered_text:
                confidence_score += 5

            if "-enc" in lowered_text or "-encodedcommand" in lowered_text:
                confidence_score += 4

            if "iex" in lowered_text:
                confidence_score += 3

            if "cmd.exe" in lowered_text:
                confidence_score += 3

            if "http" in lowered_text or "https" in lowered_text:
                confidence_score += 2

            # Penalize weird control characters or unreadable output
            weird_characters = 0

            for character in decoded_text:
                if not character.isprintable() and character not in "\r\n\t":
                    weird_characters += 1

            confidence_score -= weird_characters * 2

            if confidence_score >= 7:
                candidates.append({
                    "encoding": f"XOR Hex Key 0x{key:02X}",
                    "decoded_text": decoded_text,
                    "confidence_score": confidence_score
                })

        if not candidates:
            return []

        highest_score = max(candidate["confidence_score"] for candidate in candidates)

        best_candidates = []

        for candidate in candidates:
            if candidate["confidence_score"] == highest_score:
                candidate.pop("confidence_score", None)
                best_candidates.append(candidate)

        return best_candidates

    except Exception:
        return []

def decode_once(encoded_text):
    decoded_results = []

    decoded_results.extend(decode_base64(encoded_text))
    decoded_results.extend(decode_compressed_base64(encoded_text))
    decoded_results.extend(decode_url(encoded_text))
    decoded_results.extend(decode_hex(encoded_text))
    decoded_results.extend(decode_xor_hex(encoded_text))

    return decoded_results


def decode_input(encoded_text, max_depth=3):
    all_results = []
    seen_values = set()

    current_items = [{
        "decoded_text": encoded_text,
        "source_encoding": "Original",
        "decode_level": 0
    }]

    for level in range(1, max_depth + 1):
        next_items = []

        for item in current_items:
            decoded_text = item["decoded_text"]
            decoded_results = decode_once(decoded_text)

            for result in decoded_results:
                unique_key = f"{result['encoding']}:{result['decoded_text']}"

                if unique_key in seen_values:
                    continue

                seen_values.add(unique_key)

                result["decode_level"] = level

                if item["source_encoding"] != "Original":
                    result["source_encoding"] = item["source_encoding"]
                elif item["decode_level"] > 0:
                    result["source_encoding"] = item.get("encoding", "Unknown")

                all_results.append(result)
                next_items.append({
                    "decoded_text": result["decoded_text"],
                    "source_encoding": result["encoding"],
                    "decode_level": level
                })

        current_items = next_items

    if not all_results:
        all_results.append({
            "encoding": "Unknown",
            "decode_level": 0,
            "decoded_text": "Unable to decode input as Base64, PowerShell UTF-16LE, Gzip Base64, Deflate Base64, URL encoding, Hex, or XOR Hex."
        })

    return all_results