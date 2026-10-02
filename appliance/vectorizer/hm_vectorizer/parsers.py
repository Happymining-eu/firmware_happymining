"""Turning a file into passages.

Plain text and Markdown are read directly, with the standard library.
Everything else goes through Docling, which is optional: it is imported the
first time a file needs it. When it cannot be imported, those formats are
reported as unavailable and the files are counted as failed with the code
`parser_unavailable`; text and Markdown keep working.

The parser is given a private copy of the file with a neutral name
(`doc.<ext>`), never the path on the NAS: Docling logs the name of what it
converts, and a string that looks like a URL would be fetched.

Docling API used here, checked against the sources of Docling 2.132.0 (with
docling-core 2.99.0) installed from PyPI, and against its documentation (see
README.md, "What was verified"):

- `docling.document_converter.DocumentConverter(allowed_formats=, format_options=)`,
  `PdfFormatOption`, `ImageFormatOption`
- `.initialize_pipeline(InputFormat)`: builds the pipeline of a format and
  loads its models; it raises when they are missing
- `.convert(Path, raises_on_error=False, max_file_size=)` -> `ConversionResult`
  with `.status` (`ConversionStatus`), `.has_timeout_errors()`, `.document`
- `docling.datamodel.base_models.InputFormat`, `FormatToExtensions`
- `docling.datamodel.pipeline_options.PdfPipelineOptions` with `do_ocr`,
  `do_table_structure`, `document_timeout`; `enable_remote_services` and
  `allow_external_plugins` default to False and are left so
- `docling.chunking.HybridChunker(tokenizer=)`, `.chunk(dl_doc=)`; chunk
  `.text`, `.meta.headings`, `.meta.doc_items[*].prov[*].page_no`
- `docling_core.transforms.chunker.tokenizer.base.BaseTokenizer` (abstract
  `count_tokens`, `get_max_tokens`, `get_tokenizer`)

Models: the PDF pipeline (layout, table structure) and OCR need model files.
In the image they are downloaded when it is built and found through
`DOCLING_ARTIFACTS_PATH`, with `HF_HUB_OFFLINE=1`, so parsing contacts no
one. A format whose pipeline cannot be prepared (models missing) is reported
as `parser_unavailable` for every file of that format during the run, and
the passages already indexed for those files are kept.
"""

from __future__ import annotations

import importlib.util
import logging
from pathlib import Path
from typing import Any, Protocol

from .chunker import (
    CHUNK_MAX_CHARS,
    MAX_CHUNKS_PER_FILE,
    Chunk,
    TooManyChunks,
    enforce_limit,
    split_text,
)

log = logging.getLogger(__name__)

TEXT_EXTENSIONS = frozenset({"txt", "text"})
MARKDOWN_EXTENSIONS = frozenset({"md", "markdown"})

# Seconds one document may take in Docling before it is given up.
PARSE_TIMEOUT_S = 3600.0

# Docling input formats this service lets through, by their InputFormat name.
# Audio and video (speech recognition), remote services and the formats that
# need extra system software are left out on purpose. Images are added when
# OCR is on: without OCR an image has no text.
_DOCLING_FORMATS = ("PDF", "DOCX", "PPTX", "XLSX", "HTML", "MD", "ASCIIDOC", "CSV")
_DOCLING_OCR_FORMATS = ("IMAGE",)


class ParseError(Exception):
    """A file that cannot be turned into passages. `code` is a short reason."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class Parser(Protocol):
    def unsupported_reason(self, ext: str) -> str | None:
        """None when files with this extension can be parsed, else a reason code."""

    def parse(self, path: Path, ext: str) -> list[Chunk]:
        """Passages of the file. Raises ParseError."""


def decode_text(data: bytes) -> str:
    """Decode a text file whose encoding is not declared.

    Order: byte-order marks; UTF-16 without a mark (recognised by its zero
    bytes); strict UTF-8; then Windows-1252, which is what legacy text files on
    an office share most often are. Content that looks binary is refused.
    """
    if data.startswith(b"\xef\xbb\xbf"):
        text = _try(data[3:], "utf-8")
    elif data.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
        text = _try(data, "utf-32")
    elif data.startswith((b"\xff\xfe", b"\xfe\xff")):
        text = _try(data, "utf-16")
    elif b"\x00" in data:
        # No mark, but zero bytes: UTF-16 text, or a binary file.
        sample = data[:4096]
        even_zeros = sample[0::2].count(0)
        odd_zeros = sample[1::2].count(0)
        text = None
        if odd_zeros > len(sample) // 4 and even_zeros < len(sample) // 16:
            text = _try(data, "utf-16-le")
        elif even_zeros > len(sample) // 4 and odd_zeros < len(sample) // 16:
            text = _try(data, "utf-16-be")
    else:
        text = _try(data, "utf-8")
        if text is None:
            text = data.decode("cp1252", errors="replace")
    if text is None:
        raise ParseError("not_text")
    controls = sum(1 for ch in text if ord(ch) < 0x20 and ch not in "\t\n\r\f")
    if controls > max(8, len(text) // 50):
        raise ParseError("not_text")
    return "".join(ch for ch in text if ord(ch) >= 0x20 or ch in "\t\n\r")


def _try(data: bytes, encoding: str) -> str | None:
    try:
        return data.decode(encoding)
    except UnicodeDecodeError:
        return None


class DoclingAdapter:
    """Everything that touches Docling. Nothing is imported until it is needed."""

    def __init__(self, *, ocr: bool, timeout_s: float = PARSE_TIMEOUT_S) -> None:
        self._ocr = ocr
        self._timeout_s = timeout_s
        self._extensions: dict[str, Any] | None = None
        self._converter: Any = None
        self._chunker: Any = None
        self._chunker_tried = False
        self._installed: bool | None = None
        self._prepared: set[Any] = set()  # formats whose pipeline is ready
        self._unprepared: set[Any] = set()  # formats whose pipeline could not be prepared

    def installed(self) -> bool:
        if self._installed is None:
            try:
                self._installed = importlib.util.find_spec("docling") is not None
            except (ImportError, ValueError):
                self._installed = False
        return self._installed

    def _format_names(self) -> tuple[str, ...]:
        return _DOCLING_FORMATS + (_DOCLING_OCR_FORMATS if self._ocr else ())

    def extensions(self) -> dict[str, Any]:
        """Extension -> Docling InputFormat, for the formats let through."""
        if self._extensions is None:
            mapping: dict[str, Any] = {}
            if self.installed():
                try:
                    from docling.datamodel.base_models import FormatToExtensions, InputFormat
                except Exception:
                    log.warning("docling is installed but cannot be imported")
                    self._installed = False
                else:
                    for name in self._format_names():
                        fmt = getattr(InputFormat, name, None)
                        if fmt is None:
                            continue
                        for ext in FormatToExtensions.get(fmt, []):
                            mapping.setdefault(ext.lower(), fmt)
            self._extensions = mapping
        return self._extensions

    def _build_converter(self) -> Any:
        from docling.datamodel.base_models import InputFormat
        from docling.datamodel.pipeline_options import PdfPipelineOptions
        from docling.document_converter import DocumentConverter, ImageFormatOption, PdfFormatOption

        _quiet_libraries()
        options = PdfPipelineOptions()
        options.do_ocr = self._ocr
        options.do_table_structure = True
        options.document_timeout = self._timeout_s
        # enable_remote_services and allow_external_plugins stay False (Docling's
        # defaults): nothing of a document leaves the machine during parsing.
        allowed = [getattr(InputFormat, name) for name in self._format_names() if hasattr(InputFormat, name)]
        format_options: dict[Any, Any] = {InputFormat.PDF: PdfFormatOption(pipeline_options=options)}
        if self._ocr:
            format_options[InputFormat.IMAGE] = ImageFormatOption(pipeline_options=options)
        return DocumentConverter(allowed_formats=allowed, format_options=format_options)

    def _build_chunker(self) -> Any:
        """Docling's HybridChunker with a character budget, or None.

        Its default tokenizer is downloaded from Hugging Face and belongs to a
        model that is not the one Ollama serves; a character count needs no
        download and matches the limit used for plain text.
        """
        try:
            from docling.chunking import HybridChunker
            from docling_core.transforms.chunker.tokenizer.base import BaseTokenizer
        except Exception:
            log.warning("docling chunker unavailable: using the built-in splitter")
            return None

        class CharacterBudget(BaseTokenizer):
            max_chars: int = CHUNK_MAX_CHARS

            def count_tokens(self, text: str) -> int:
                return len(text)

            def get_max_tokens(self) -> int:
                return self.max_chars

            def get_tokenizer(self) -> Any:
                return len

        try:
            return HybridChunker(tokenizer=CharacterBudget())
        except Exception:
            log.warning("docling chunker could not be created: using the built-in splitter")
            return None

    def prepare(self, fmt: Any) -> None:
        """Build the converter and the pipeline of this format once per run.

        A pipeline that cannot be built (its models are missing, or would have
        to be downloaded and cannot be) is a problem of the machine, not of
        the document: every file of that format is `parser_unavailable` until
        the next run, and nothing is tried again for each of them.
        """
        if fmt in self._unprepared:
            raise ParseError("parser_unavailable")
        if fmt in self._prepared:
            return
        try:
            if self._converter is None:
                self._converter = self._build_converter()
            self._converter.initialize_pipeline(fmt)
        except Exception as exc:
            log.warning(
                "docling cannot prepare the %s pipeline (%s): its files count as parser_unavailable",
                getattr(fmt, "value", "?"),
                exc.__class__.__name__,
            )
            log.debug("docling pipeline failure", exc_info=True)
            self._unprepared.add(fmt)
            raise ParseError("parser_unavailable") from None
        finally:
            _quiet_libraries()  # a library imported by the pipeline may have reset its own level
        self._prepared.add(fmt)

    def parse(self, path: Path, ext: str, max_file_bytes: int) -> list[Chunk]:
        fmt = self.extensions().get(ext)
        if fmt is None:
            raise ParseError("unsupported_format")
        self.prepare(fmt)
        try:
            from docling.datamodel.base_models import ConversionStatus

            result = self._converter.convert(path, raises_on_error=False, max_file_size=max_file_bytes)
        except Exception as exc:
            log.debug("docling conversion raised %s", exc.__class__.__name__, exc_info=True)
            raise ParseError("parse_error") from None
        if result.status != ConversionStatus.SUCCESS:
            timed_out = getattr(result, "has_timeout_errors", None)
            if result.status == ConversionStatus.PARTIAL_SUCCESS and callable(timed_out) and timed_out():
                raise ParseError("parse_timeout")
            raise ParseError("parse_error")
        document = result.document

        if not self._chunker_tried:
            self._chunker_tried = True
            self._chunker = self._build_chunker()
        if self._chunker is None:
            return self._fallback_chunks(document)
        try:
            chunks: list[Chunk] = []
            for item in self._chunker.chunk(dl_doc=document):
                text = (item.text or "").strip()
                if not text:
                    continue
                chunks.append(Chunk(text=text, headings=_headings(item), page=_first_page(item)))
                if len(chunks) > MAX_CHUNKS_PER_FILE:
                    raise ParseError("too_many_chunks")
        except ParseError:
            raise
        except Exception as exc:
            log.debug("docling chunking raised %s", exc.__class__.__name__, exc_info=True)
            return self._fallback_chunks(document)
        return enforce_limit(chunks)

    @staticmethod
    def _fallback_chunks(document: Any) -> list[Chunk]:
        try:
            markdown = document.export_to_markdown()
        except Exception:
            raise ParseError("parse_error") from None
        try:
            return split_text(markdown, markdown=True)
        except TooManyChunks:
            raise ParseError("too_many_chunks") from None


_QUIET_LOGGERS = ("docling", "docling_core", "docling_parse", "docling_ibm_models", "RapidOCR")


def _at_least_warning(record: logging.LogRecord) -> bool:
    return record.levelno >= logging.WARNING


def _quiet_libraries() -> None:
    """Keep the parsing libraries at WARNING.

    Docling logs the name of each document at INFO; the names it sees are
    neutral (`doc.<ext>`), but its progress lines are not ours to emit.
    RapidOCR logs under "RapidOCR" through a handler of its own and sets its
    logger back to INFO when it builds one, so a filter on the logger itself
    (which a level change does not remove) does the job.
    """
    for name in _QUIET_LOGGERS:
        logger = logging.getLogger(name)
        logger.setLevel(logging.WARNING)
        if _at_least_warning not in logger.filters:
            logger.addFilter(_at_least_warning)


def _headings(item: Any) -> tuple[str, ...]:
    headings = getattr(getattr(item, "meta", None), "headings", None) or ()
    return tuple(str(h) for h in headings)


def _first_page(item: Any) -> int | None:
    pages: list[int] = []
    for doc_item in getattr(getattr(item, "meta", None), "doc_items", None) or ():
        for prov in getattr(doc_item, "prov", None) or ():
            page_no = getattr(prov, "page_no", None)
            if isinstance(page_no, int):
                pages.append(page_no)
    return min(pages) if pages else None


class DefaultParser:
    """Text and Markdown directly; the rest through Docling when it is installed."""

    def __init__(self, *, ocr: bool, max_file_bytes: int) -> None:
        self._docling = DoclingAdapter(ocr=ocr)
        self._max_file_bytes = max_file_bytes

    def unsupported_reason(self, ext: str) -> str | None:
        if ext in TEXT_EXTENSIONS or ext in MARKDOWN_EXTENSIONS:
            return None
        if not self._docling.installed():
            return "parser_unavailable"
        if ext not in self._docling.extensions():
            # extensions() can find out that the import fails after all.
            return "unsupported_format" if self._docling.installed() else "parser_unavailable"
        return None

    def parse(self, path: Path, ext: str) -> list[Chunk]:
        if ext in TEXT_EXTENSIONS or ext in MARKDOWN_EXTENSIONS:
            try:
                data = path.read_bytes()
            except OSError:
                raise ParseError("read_error") from None
            text = decode_text(data)
            try:
                chunks = split_text(text, markdown=ext in MARKDOWN_EXTENSIONS)
            except TooManyChunks:
                raise ParseError("too_many_chunks") from None
        else:
            chunks = self._docling.parse(path, ext, self._max_file_bytes)
        if not chunks:
            raise ParseError("no_text")
        return chunks
