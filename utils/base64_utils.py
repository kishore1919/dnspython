import base64


def encode_base64(text: str) -> str:
    """
    Encode a string to base64.
    Returns the base64-encoded string.
    """
    try:
        encoded_bytes = base64.b64encode(text.encode('utf-8'))
        return encoded_bytes.decode('ascii')
    except Exception:
        return "Encoding error"


def decode_base64(encoded_text: str) -> str:
    """
    Decode a base64-encoded string, handling missing padding.
    Returns the decoded string, or "Invalid base64" if decoding fails.
    """
    try:
        cleaned = str(encoded_text).replace(" ", "").replace("\n", "")
        padded = cleaned + '=' * ((4 - len(cleaned) % 4) % 4)
        decoded_bytes = base64.b64decode(padded, validate=True)
        return decoded_bytes.decode('utf-8')
    except Exception:
        return "Invalid base64"