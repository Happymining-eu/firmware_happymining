"""Cutting text into passages.

`split_text` is the splitter used for plain text and Markdown, and the
fall-back for Docling documents when Docling's own chunker cannot be loaded.
It keeps paragraphs together, respects a size limit, and repeats the end of a
passage at the start of the next one (overlap). For Markdown it records the
headings above each passage.

Sizes are counted in characters, not in model tokens: the embedding model is
served by Ollama and its tokenizer is not available here. 1600 characters is
far below the context window of the embedding models this is used with; a
longer input would be truncated by Ollama, not refused.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

CHUNK_MAX_CHARS = 1600
CHUNK_OVERLAP_CHARS = 200
MAX_CHUNKS_PER_FILE = 20000

_HEADING = re.compile(r"^(#{1,6})[ \t]+(.+?)[ \t]*#*[ \t]*$")
_FENCE = re.compile(r"^[ \t]{0,3}(```|~~~)")
_BLANK_LINES = re.compile(r"\n[ \t]*\n+")
# Sentence ends, including the CJK full stop, exclamation mark and question mark.
_SENTENCE_END = re.compile("(?<=[.!?;:\u3002\uff01\uff1f])\\s+")
_WHITESPACE = re.compile(r"\s+")


class TooManyChunks(Exception):
    """The document would produce more passages than one file may have."""


@dataclass(frozen=True)
class Chunk:
    text: str
    headings: tuple[str, ...] = ()
    page: int | None = None

    @property
    def embed_text(self) -> str:
        """What is embedded: the headings give the passage its context."""
        return "\n".join((*self.headings, self.text))


def split_text(
    text: str,
    *,
    markdown: bool,
    max_chars: int = CHUNK_MAX_CHARS,
    overlap: int = CHUNK_OVERLAP_CHARS,
    max_chunks: int = MAX_CHUNKS_PER_FILE,
) -> list[Chunk]:
    if not 0 <= overlap < max_chars // 2:
        raise ValueError("overlap must be smaller than half the passage size")
    body_budget = max_chars - overlap
    if len(text) > max_chunks * body_budget:
        raise TooManyChunks
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    chunks: list[Chunk] = []
    for headings, section in _sections(text, markdown):
        previous_tail = ""
        for body in _pack(_paragraphs(section), body_budget):
            chunks.append(Chunk(text=(previous_tail + body).strip(), headings=headings))
            if len(chunks) > max_chunks:
                raise TooManyChunks
            previous_tail = _tail(body, overlap)
    return [chunk for chunk in chunks if chunk.text]


def _sections(text: str, markdown: bool) -> list[tuple[tuple[str, ...], str]]:
    """Split Markdown at ATX headings; plain text is one section."""
    if not markdown:
        return [((), text)]
    sections: list[tuple[tuple[str, ...], str]] = []
    stack: list[tuple[int, str]] = []
    current: list[str] = []
    in_fence = False

    def flush() -> None:
        if current:
            sections.append((tuple(title for _, title in stack), "\n".join(current)))
            current.clear()

    for line in text.split("\n"):
        if _FENCE.match(line):
            in_fence = not in_fence
        heading = None if in_fence else _HEADING.match(line)
        if heading is None:
            current.append(line)
            continue
        flush()
        level = len(heading.group(1))
        while stack and stack[-1][0] >= level:
            stack.pop()
        stack.append((level, heading.group(2).strip()))
    flush()
    return sections


def _paragraphs(section: str) -> list[str]:
    return [p.strip() for p in _BLANK_LINES.split(section) if p.strip()]


def _pack(paragraphs: list[str], budget: int) -> list[str]:
    """Group paragraphs into bodies of at most `budget` characters."""
    bodies: list[str] = []
    current = ""
    for paragraph in paragraphs:
        pieces = [paragraph] if len(paragraph) <= budget else _split_long(paragraph, budget)
        for piece in pieces:
            if not current:
                current = piece
            elif len(current) + 2 + len(piece) <= budget:
                current = f"{current}\n\n{piece}"
            else:
                bodies.append(current)
                current = piece
    if current:
        bodies.append(current)
    return bodies


def _split_long(paragraph: str, budget: int) -> list[str]:
    """Cut a paragraph that is too long: at sentence ends, then words, then anywhere."""
    pieces: list[str] = []
    current = ""
    for sentence in _SENTENCE_END.split(paragraph):
        for unit in [sentence] if len(sentence) <= budget else _split_words(sentence, budget):
            if not current:
                current = unit
            elif len(current) + 1 + len(unit) <= budget:
                current = f"{current} {unit}"
            else:
                pieces.append(current)
                current = unit
    if current:
        pieces.append(current)
    return pieces


def _split_words(sentence: str, budget: int) -> list[str]:
    pieces: list[str] = []
    current = ""
    for word in _WHITESPACE.split(sentence):
        while len(word) > budget:
            if current:
                pieces.append(current)
                current = ""
            pieces.append(word[:budget])
            word = word[budget:]
        if not word:
            continue
        if not current:
            current = word
        elif len(current) + 1 + len(word) <= budget:
            current = f"{current} {word}"
        else:
            pieces.append(current)
            current = word
    if current:
        pieces.append(current)
    return pieces


def _tail(body: str, overlap: int) -> str:
    """The end of a passage, repeated at the start of the next one."""
    if overlap <= 0 or len(body) <= overlap:
        return ""
    tail = body[-overlap:]
    cut = _WHITESPACE.search(tail)
    if cut is None:
        return ""
    tail = tail[cut.end() :]
    return f"{tail}\n" if tail else ""


def enforce_limit(chunks: list[Chunk], *, max_chars: int = CHUNK_MAX_CHARS) -> list[Chunk]:
    """Cut passages produced by another chunker that are longer than the limit."""
    out: list[Chunk] = []
    for chunk in chunks:
        if len(chunk.text) <= max_chars:
            out.append(chunk)
            continue
        for piece in _split_long(chunk.text, max_chars):
            out.append(Chunk(text=piece, headings=chunk.headings, page=chunk.page))
    return out
