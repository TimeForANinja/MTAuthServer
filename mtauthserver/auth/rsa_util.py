import base64

def minimize_rsa_key(pem_key: str) -> str:
    # 1. Remove PEM headers, footers and whitespace/newlines
    lines = pem_key.strip().splitlines()
    inner_b64 = "".join(l for l in lines if not l.startswith("---"))

    # 2. Decode the standard Base64 to get raw bytes
    raw_der = base64.b64decode(inner_b64)

    # 3. Use URL-safe Base64 and strip the padding ('=')
    # This is safe because URLs don't need padding to be parsed correctly
    minimized = base64.urlsafe_b64encode(raw_der).decode('utf-8').rstrip("=")

    return minimized

def restore_rsa_key(minimzed_key: str) -> str:
    # Add padding back if neccessary
    padding = len(minimzed_key) % 4
    if padding:
        minimzed_key += "=" * (4 -padding)

    # Standard base64 decode from url-safe alphabet
    raw_der = base64.urlsafe_b64decode(minimzed_key)

    # Re-encode to standard B64 for PEM format
    b64_str = base64.urlsafe_b64encode(raw_der).decode('utf-8')

    return "-----BEGIN PUBLIC KEY-----\n" + b64_str + "\n-----END PUBLIC KEY-----"
