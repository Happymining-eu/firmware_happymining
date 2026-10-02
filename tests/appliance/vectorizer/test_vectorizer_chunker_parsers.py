"""The built-in splitter and the direct readers for text and Markdown."""

from __future__ import annotations

import enum
import importlib.util
import itertools
import logging
import sys
import types
from pathlib import Path
from typing import Any

import pytest
from hm_vectorizer import parsers
from hm_vectorizer.chunker import Chunk, TooManyChunks, enforce_limit, split_text
from hm_vectorizer.parsers import DefaultParser, ParseError, decode_text


def test_short_text_is_one_passage() -> None:
    chunks = split_text("One paragraph.\n\nAnother one.", markdown=False)
    assert chunks == [Chunk(text="One paragraph.\n\nAnother one.")]


def test_paragraphs_are_kept_whole_and_the_limit_is_respected() -> None:
    paragraphs = [f"Paragraph {i} " + "word " * 30 for i in range(12)]
    chunks = split_text("\n\n".join(paragraphs), markdown=False, max_chars=400, overlap=60)
    assert len(chunks) > 3
    assert all(len(c.text) <= 400 for c in chunks)
    joined = "\n".join(c.text for c in chunks)
    for paragraph in paragraphs:
        assert paragraph.strip() in joined  # no paragraph was cut


def test_consecutive_passages_overlap() -> None:
    paragraphs = [f"Sentence number {i} about the cooling loop of container {i}." for i in range(40)]
    chunks = split_text("\n\n".join(paragraphs), markdown=False, max_chars=300, overlap=80)
    assert len(chunks) > 2
    assert all(len(c.text) <= 300 for c in chunks)
    for before, after in itertools.pairwise(chunks):
        shared = max(n for n in range(81) if before.text.endswith(after.text[:n]))
        assert 20 <= shared <= 80, "the start of a passage repeats the end of the last one"
        assert not after.text[:shared][0].isspace() and before.text[-shared - 1].isspace(), (
            "cut between words"
        )


def test_no_overlap_when_asked() -> None:
    paragraphs = [f"Sentence number {i} about the cooling loop." for i in range(40)]
    chunks = split_text("\n\n".join(paragraphs), markdown=False, max_chars=300, overlap=0)
    assert "\n\n".join(c.text for c in chunks) == "\n\n".join(paragraphs)


def test_long_paragraph_is_cut_at_sentence_ends() -> None:
    sentences = [f"This is sentence {i} of a very long paragraph." for i in range(60)]
    chunks = split_text(" ".join(sentences), markdown=False, max_chars=300, overlap=0)
    assert all(len(c.text) <= 300 for c in chunks)
    assert all(c.text.endswith(".") for c in chunks)
    assert " ".join(c.text for c in chunks) == " ".join(sentences)


def test_text_without_spaces_is_cut_anyway() -> None:
    chunks = split_text("x" * 2500, markdown=False, max_chars=1000, overlap=0)
    assert [len(c.text) for c in chunks] == [1000, 1000, 500]


def test_markdown_passages_carry_their_headings() -> None:
    text = (
        "Preamble before any heading.\n\n"
        "# Handbook\n\nIntroduction.\n\n"
        "## Pumps\n\nPump text.\n\n"
        "### Seals ###\n\nSeal text.\n\n"
        "## Valves\n\nValve text.\n\n"
        "```\n# not a heading, a comment in code\n```\n"
    )
    chunks = split_text(text, markdown=True)
    assert [(c.headings, c.text.split("\n")[0]) for c in chunks] == [
        ((), "Preamble before any heading."),
        (("Handbook",), "Introduction."),
        (("Handbook", "Pumps"), "Pump text."),
        (("Handbook", "Pumps", "Seals"), "Seal text."),
        (("Handbook", "Valves"), "Valve text."),
    ]
    assert "# not a heading" in chunks[-1].text
    assert chunks[2].embed_text == "Handbook\nPumps\nPump text."
    assert all(c.page is None for c in chunks)


def test_plain_text_does_not_read_headings() -> None:
    (chunk,) = split_text("# Title\n\nBody.", markdown=False)
    assert chunk.headings == () and chunk.text.startswith("# Title")


def test_overlap_does_not_cross_a_heading() -> None:
    text = "# A\n\n" + "alpha " * 100 + "\n\n# B\n\nbeta start."
    chunks = split_text(text, markdown=True, max_chars=300, overlap=80)
    last = chunks[-1]
    assert last.headings == ("B",) and last.text == "beta start."


def test_empty_and_blank_text_give_nothing() -> None:
    assert split_text("", markdown=False) == []
    assert split_text(" \n\n\t\n", markdown=True) == []
    assert split_text("# Only\n\n## Headings\n", markdown=True) == []


def test_too_many_passages() -> None:
    with pytest.raises(TooManyChunks):
        split_text("word " * 5000, markdown=False, max_chars=100, overlap=10, max_chunks=20)


def test_enforce_limit_cuts_passages_of_another_chunker() -> None:
    long = Chunk(text="Sentence one. " * 300, headings=("H",), page=7)
    short = Chunk(text="short")
    out = enforce_limit([long, short], max_chars=500)
    assert out[-1] == short
    assert len(out) > 5 and all(len(c.text) <= 500 for c in out)
    assert all(c.headings == ("H",) and c.page == 7 for c in out[:-1])


# -- encodings ------------------------------------------------------------------

SAMPLE = "Résumé du contrat n° 12 — € 1 250,00\nDeuxième ligne."


@pytest.mark.parametrize(
    "data",
    [
        SAMPLE.encode("utf-8"),
        b"\xef\xbb\xbf" + SAMPLE.encode("utf-8"),
        SAMPLE.encode("utf-16"),  # with a byte-order mark
        SAMPLE.encode("utf-16-le"),
        SAMPLE.encode("utf-16-be"),
        SAMPLE.encode("utf-32"),
        SAMPLE.encode("cp1252"),
    ],
    ids=["utf8", "utf8-bom", "utf16-bom", "utf16le", "utf16be", "utf32-bom", "cp1252"],
)
def test_text_is_decoded_whatever_its_encoding(data: bytes) -> None:
    assert decode_text(data) == SAMPLE


def test_control_characters_are_dropped() -> None:
    assert decode_text(b"a\x0cb\x01c\td\ne") == "abc\td\ne"


@pytest.mark.parametrize(
    "data",
    [
        bytes(range(256)) * 20,
        b"%PDF-1.4\n" + bytes([0, 1, 2, 3, 0, 0, 7, 200, 0]) * 500,
        b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR" + bytes(range(0, 32)) * 40,
    ],
)
def test_binary_content_is_not_text(data: bytes) -> None:
    with pytest.raises(ParseError) as caught:
        decode_text(data)
    assert caught.value.code == "not_text"


# -- the default parser ---------------------------------------------------------------


@pytest.fixture
def no_docling(monkeypatch: pytest.MonkeyPatch) -> None:
    """Behave as on a machine where Docling is not installed, whatever this interpreter has."""
    real = importlib.util.find_spec

    def find_spec(name: str, package: str | None = None):  # type: ignore[no-untyped-def]
        return None if name == "docling" else real(name, package)

    monkeypatch.setattr(parsers.importlib.util, "find_spec", find_spec)


def test_text_and_markdown_need_no_docling(tmp_path: Path, no_docling: None) -> None:
    parser = DefaultParser(ocr=False, max_file_bytes=1024 * 1024)
    for ext in ("txt", "text", "md", "markdown"):
        assert parser.unsupported_reason(ext) is None
    path = tmp_path / "doc.md"
    path.write_text("# Title\n\nBody text.", encoding="utf-8")
    assert parser.parse(path, "md") == [Chunk(text="Body text.", headings=("Title",))]
    path = tmp_path / "doc.txt"
    path.write_bytes("Texte accentué.".encode("cp1252"))
    assert parser.parse(path, "txt") == [Chunk(text="Texte accentué.")]


def test_other_formats_are_unavailable_without_docling(no_docling: None) -> None:
    parser = DefaultParser(ocr=False, max_file_bytes=1024 * 1024)
    for ext in ("pdf", "docx", "pptx", "xlsx", "html", "zip"):
        assert parser.unsupported_reason(ext) == "parser_unavailable"


def test_text_without_content_and_binary_text_fail_with_a_code(tmp_path: Path, no_docling: None) -> None:
    parser = DefaultParser(ocr=False, max_file_bytes=1024 * 1024)
    blank = tmp_path / "doc.txt"
    blank.write_text("  \n\n ")
    with pytest.raises(ParseError) as caught:
        parser.parse(blank, "txt")
    assert caught.value.code == "no_text"
    binary = tmp_path / "doc.md"
    binary.write_bytes(bytes(range(256)) * 8)
    with pytest.raises(ParseError) as caught:
        parser.parse(binary, "md")
    assert caught.value.code == "not_text"
    with pytest.raises(ParseError) as caught:
        parser.parse(tmp_path / "absent.txt", "txt")
    assert caught.value.code == "read_error"


class _Status(enum.Enum):
    SUCCESS = "success"
    PARTIAL_SUCCESS = "partial_success"
    FAILURE = "failure"


class _Format(enum.Enum):
    PDF = "pdf"
    DOCX = "docx"


class _Document:
    def export_to_markdown(self) -> str:
        return "# Title\n\nConverted body."


class _Converter:
    """Stands for DocumentConverter: the PDF pipeline cannot be built (its models
    cannot be downloaded), the DOCX one can."""

    def __init__(self) -> None:
        self.initialized: list[_Format] = []
        self.converted: list[Path] = []

    def initialize_pipeline(self, fmt: _Format) -> None:
        self.initialized.append(fmt)
        if fmt is _Format.PDF:
            raise OSError("ProxyError 403 while fetching the layout model")

    def convert(self, path: Path, *, raises_on_error: bool, max_file_size: int) -> Any:
        self.converted.append(path)
        if path.suffix == ".pdf":
            raise OSError("ProxyError 403 while fetching the layout model")
        return types.SimpleNamespace(status=_Status.SUCCESS, document=_Document())


@pytest.fixture
def fake_docling(monkeypatch: pytest.MonkeyPatch) -> _Converter:
    """Just enough of Docling's modules for DoclingAdapter.parse, whatever this interpreter has."""
    base_models = types.ModuleType("docling.datamodel.base_models")
    base_models.ConversionStatus = _Status  # type: ignore[attr-defined]
    for name, module in (
        ("docling", types.ModuleType("docling")),
        ("docling.datamodel", types.ModuleType("docling.datamodel")),
        ("docling.datamodel.base_models", base_models),
        ("docling.chunking", None),  # the chunker cannot be imported: the built-in splitter is used
    ):
        monkeypatch.setitem(sys.modules, name, module)
    return _Converter()


def test_format_whose_pipeline_cannot_be_prepared_is_unavailable_not_broken(
    tmp_path: Path, fake_docling: _Converter
) -> None:
    adapter = parsers.DoclingAdapter(ocr=False)
    adapter._installed = True
    adapter._extensions = {"pdf": _Format.PDF, "docx": _Format.DOCX}
    adapter._converter = fake_docling
    for name in ("a.pdf", "b.pdf"):
        (tmp_path / name).write_bytes(b"%PDF-1.4")
        with pytest.raises(ParseError) as caught:
            adapter.parse(tmp_path / name, "pdf", 1024)
        assert caught.value.code == "parser_unavailable", "a machine problem, not a broken document"
    assert fake_docling.initialized.count(_Format.PDF) == 1, "tried once per run, not once per file"
    assert fake_docling.converted == [], "no document of that format is handed to Docling"

    for name in ("c.docx", "d.docx"):
        (tmp_path / name).write_bytes(b"PK")
        assert adapter.parse(tmp_path / name, "docx", 1024) == [
            Chunk(text="Converted body.", headings=("Title",))
        ]
    assert fake_docling.initialized.count(_Format.DOCX) == 1
    with pytest.raises(ParseError) as caught:
        adapter.parse(tmp_path / "c.docx", "zip", 1024)
    assert caught.value.code == "unsupported_format"


def test_ocr_library_stays_quiet_even_when_it_resets_its_level() -> None:
    logger = logging.getLogger("RapidOCR")
    seen: list[str] = []

    class Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            seen.append(record.getMessage())

    handler = Capture()
    saved_level, saved_propagate = logger.level, logger.propagate
    logger.addHandler(handler)
    logger.propagate = False
    try:
        parsers._quiet_libraries()
        logger.setLevel(logging.INFO)  # what RapidOCR does when it builds an engine
        logger.info("Initiating download: https://www.modelscope.cn/models/...")
        logger.warning("Download failed")
    finally:
        logger.removeHandler(handler)
        logger.removeFilter(parsers._at_least_warning)
        logger.setLevel(saved_level)
        logger.propagate = saved_propagate
    assert seen == ["Download failed"]


def test_selfcheck_fails_without_docling(no_docling: None, capsys: pytest.CaptureFixture[str]) -> None:
    from hm_vectorizer.__main__ import main

    assert main(["selfcheck"]) == 1
    assert "docling: not installed" in capsys.readouterr().out


def test_selfcheck_pdf_carries_its_marker_in_a_text_layer() -> None:
    """What the self-check looks for after conversion is really in the PDF it writes."""
    from hm_vectorizer.selfcheck import MARKER, minimal_pdf

    data = minimal_pdf([MARKER])
    assert data.startswith(b"%PDF-1.4\n") and data.endswith(b"%%EOF\n")
    assert f"({MARKER}) Tj".encode() in data


def test_docling_that_cannot_be_imported_counts_as_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    """Installed but broken (a missing shared library, say): same answer as not installed."""
    monkeypatch.setattr(parsers.importlib.util, "find_spec", lambda name, package=None: object())
    import builtins

    real_import = builtins.__import__

    def failing_import(name: str, *args: object, **kwargs: object):  # type: ignore[no-untyped-def]
        if name.startswith("docling"):
            raise ImportError("libGL.so.1: cannot open shared object file")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", failing_import)
    parser = DefaultParser(ocr=False, max_file_bytes=1024)
    assert parser.unsupported_reason("pdf") == "parser_unavailable"
    assert parser.unsupported_reason("txt") is None
