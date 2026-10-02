"""`python -m hm_vectorizer selfcheck`: can this installation parse documents
with nothing but what it has on disk?

Run once when the image is built (see the Dockerfile), as the user the
service runs as and with `HF_HUB_OFFLINE=1`. For OCR off and then on, it
prepares the Docling pipeline of every format the service lets through and
converts a one-page PDF written here, then checks that its text came out. A
model file that is missing makes the build fail instead of every PDF failing
later on the machine.

It prints format names and outcomes only. Exit 0 when everything works, 1
otherwise (Docling missing included).
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path
from typing import TextIO

from .parsers import DoclingAdapter, ParseError

MARKER = "HappyMining selfcheck 4711"


def minimal_pdf(lines: list[str]) -> bytes:
    """A one-page PDF with a text layer, written without any library."""
    content = "BT /F1 12 Tf 72 720 Td 14 TL " + " ".join(f"({line}) Tj T*" for line in lines) + " ET"
    objects = [
        "<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
        "/Resources << /Font << /F1 5 0 R >> >> >>",
        f"<< /Length {len(content)} >>\nstream\n{content}\nendstream",
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    body = "%PDF-1.4\n"
    offsets = []
    for number, obj in enumerate(objects, start=1):
        offsets.append(len(body))
        body += f"{number} 0 obj\n{obj}\nendobj\n"
    xref = len(body)
    body += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n"
    body += "".join(f"{offset:010d} 00000 n \n" for offset in offsets)
    body += f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n"
    return body.encode("latin-1")


def run(out: TextIO | None = None) -> int:
    out = out if out is not None else sys.stdout  # looked up now: it may have been replaced
    ok = True
    with tempfile.TemporaryDirectory(prefix="hm-selfcheck-") as tmp:
        pdf = Path(tmp) / "doc.pdf"
        pdf.write_bytes(minimal_pdf([MARKER, "Total due: 1250.00 EUR"]))
        for ocr in (False, True):
            adapter = DoclingAdapter(ocr=ocr)
            formats = adapter.extensions() if adapter.installed() else {}
            if not formats:
                print("docling: not installed or cannot be imported", file=out)
                return 1
            for fmt in sorted(set(formats.values()), key=lambda f: str(getattr(f, "value", f))):
                name = getattr(fmt, "value", str(fmt))
                try:
                    adapter.prepare(fmt)
                except ParseError:
                    ok = False
                    print(f"ocr={ocr} {name}: pipeline cannot be prepared", file=out)
                else:
                    print(f"ocr={ocr} {name}: ready", file=out)
            try:
                chunks = adapter.parse(pdf, "pdf", 1024 * 1024)
            except ParseError as exc:
                ok = False
                print(f"ocr={ocr} pdf conversion: failed ({exc.code})", file=out)
            else:
                found = any(MARKER in chunk.text for chunk in chunks)
                ok = ok and found
                print(f"ocr={ocr} pdf conversion: {'ok' if found else 'text not found'}", file=out)
    print("selfcheck: " + ("ok" if ok else "FAILED"), file=out)
    return 0 if ok else 1
