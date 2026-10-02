"""Shared pieces of the vectorizer tests: where the package is, the fake
machine (`Site`) and the constants. Importing this module puts
`appliance/vectorizer` on `sys.path`.
"""

from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[3]
# HM_VECTORIZER_SRC points the tests at another copy of the package (an installed one, or a
# deliberately broken one when checking that a test fails without the check it is there for).
VECTORIZER_DIR = Path(os.environ.get("HM_VECTORIZER_SRC") or REPO / "appliance" / "vectorizer")
if str(VECTORIZER_DIR) not in sys.path:
    sys.path.insert(0, str(VECTORIZER_DIR))

from hm_vectorizer import config as vz_config  # noqa: E402

TOKEN = "tok-3f9a1c7e5b2d4f6a8c0e1b3d5f7a9c2e"
API_KEY = "sk-test-KEY-7c1d9e2f4a6b8c0d1e3f5a7b9c2d4e6f"


@dataclass
class Site:
    """A fake machine: NAS root, /config and /state as temporary directories."""

    root: Path
    nas_root: Path
    config_dir: Path
    state_dir: Path
    document: dict[str, Any]

    def source_dir(self, source_id: str = "docs") -> Path:
        return self.nas_root / source_id

    def write(
        self, rel_path: str, content: str | bytes, *, source_id: str = "docs", age_s: float = 3600
    ) -> Path:
        """Create a file in a source. Its modification time is set in the past
        so that the "modified a moment ago" rule does not apply by accident."""
        path = self.source_dir(source_id) / rel_path
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, str):
            path.write_text(content, encoding="utf-8")
        else:
            path.write_bytes(content)
        stamp = time.time() - age_s
        os.utime(path, (stamp, stamp))
        return path

    def save(self, **changes: Any) -> vz_config.Config:
        """Write vectorizer.json (with these keys replaced) and load it."""
        self.document.update(changes)
        (self.config_dir / "vectorizer.json").write_text(json.dumps(self.document), encoding="utf-8")
        return self.load()

    def load(self) -> vz_config.Config:
        return vz_config.load_config(self.config_dir / "vectorizer.json", nas_root=str(self.nas_root))


def base_document(nas_root: Path, ollama_url: str, qdrant_url: str) -> dict[str, Any]:
    return {
        "sources": ["docs"],
        "extensions": ["pdf", "docx", "pptx", "xlsx", "html", "md", "txt"],
        "exclude": ["#recycle", "private/hr"],
        "max_file_mib": 1,
        "embedding_model": "bge-m3",
        "ocr": False,
        "answer": {"provider": "none"},
        "source_paths": {"docs": f"{nas_root}/docs"},
        "ollama_url": ollama_url,
        "qdrant_url": qdrant_url,
        "collection": "happymining_docs",
    }
