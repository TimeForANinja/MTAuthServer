import base64
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


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
    b64_str = base64.b64encode(raw_der).decode('utf-8')

    # Split into lines for PEM format
    b64_str = "\n".join([b64_str[i:i+64] for i in range(0, len(b64_str), 64)])

    return "-----BEGIN PUBLIC KEY-----\n" + b64_str + "\n-----END PUBLIC KEY-----"

def generate_dummy_keypair() -> Tuple[str, str]:
    """
    Generate a dummy RSA keypair for testing purposes.
    In production, you should use static keypair and import it via env.
    :return:
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    return priv_pem, pub_pem
