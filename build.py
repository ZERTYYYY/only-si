"""Génère index.html : le site de source/ chiffré (AES-256-GCM, clé dérivée du code par PBKDF2).

Usage : python build.py            (le code est demandé au clavier)
        python build.py MONCODE

Les images de source/images sont intégrées dans la page avant chiffrement,
donc rien de lisible n'est publié sans le code.
"""
import base64, getpass, json, mimetypes, os, re, sys
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

ROOT = Path(__file__).parent
SRC = ROOT / "source"
ITERATIONS = 600_000


def inline_images(html: str) -> str:
    def to_data_uri(m):
        path = SRC / m.group(2)
        mime = mimetypes.guess_type(path.name)[0] or "image/jpeg"
        data = base64.b64encode(path.read_bytes()).decode()
        return f"{m.group(1)}data:{mime};base64,{data}"
    return re.sub(r'(src="|url\()(images/[\w.-]+)', to_data_uri, html)


def main():
    password = sys.argv[1] if len(sys.argv) > 1 else getpass.getpass("Code d'accès : ")
    if not password:
        sys.exit("Code vide.")

    html = inline_images((SRC / "index.html").read_text(encoding="utf-8"))

    salt, iv = os.urandom(16), os.urandom(12)
    key = PBKDF2HMAC(hashes.SHA256(), 32, salt, ITERATIONS).derive(password.encode())
    cipher = AESGCM(key).encrypt(iv, html.encode("utf-8"), None)

    payload = json.dumps({
        "s": base64.b64encode(salt).decode(),
        "i": base64.b64encode(iv).decode(),
        "c": base64.b64encode(cipher).decode(),
        "n": ITERATIONS,
    })
    gate = (ROOT / "gate.html").read_text(encoding="utf-8").replace("__PAYLOAD__", payload)
    (ROOT / "index.html").write_text(gate, encoding="utf-8")
    print(f"index.html généré ({len(gate) // 1024} Ko).")


if __name__ == "__main__":
    main()
