import base64

def decode_base64(encoded_text):
    try:
        decoded_bytes = base64.b64decode(encoded_text)
        decoded_text = decoded_bytes.decode("utf-8", errors="ignore")
        return decoded_text
    except Exception as error:
        return f"Error decoding Base64: {error}"

def check_suspicious_keywords(decoded_text):
    suspicious_keywords = [
        "powershell",
        "invoke-expression",
        "iex",
        "downloadstring",
        "frombase64string",
        "webclient",
        "encodedcommand",
        "start-process",
        "cmd.exe",
        "http",
        "https"
    ]

    found_keywords = []

    for keyword in suspicious_keywords:
        if keyword in decoded_text.lower():
            found_keywords.append(keyword)

    return found_keywords

def main():
    print("====================================")
    print(" Base64 Decoder Detection App")
    print("====================================")

    encoded_text = input("Paste Base64 string: ")

    decoded_text = decode_base64(encoded_text)

    print("\nDecoded Output:")
    print("------------------------------------")
    print(decoded_text)

    found_keywords = check_suspicious_keywords(decoded_text)

    print("\nSuspicious Keyword Check:")
    print("------------------------------------")

    if found_keywords:
        print("Suspicious keywords found:")
        for keyword in found_keywords:
            print(f"- {keyword}")
    else:
        print("No suspicious keywords found.")

if __name__ == "__main__":
    main()