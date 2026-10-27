import os
from pathlib import Path
import pypdf # or we can use basic binary inspection or pdfminer or reportlab

user_upload_dir = Path(r"C:\Users\OM\.gemini\antigravity\brain\442e5ece-4ce7-4b94-a44b-d52db3a3ecb0\.user_uploaded")

for f in sorted(user_upload_dir.glob("*.pdf")):
    size = f.stat().st_size
    # Read first 1000 bytes to get header or text
    with open(f, "rb") as fp:
        raw = fp.read(2000)
    print(f"{f.name} ({size} bytes)")

