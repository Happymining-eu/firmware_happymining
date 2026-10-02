"""HappyMining NAS vectorizer.

Indexes documents from read-only NAS mounts into Qdrant and answers searches
and questions on the owner's network. Contract: docs/appliance.md, sections
4.4 and 11. The core uses the standard library only; Docling is optional and
loaded lazily by `parsers`.
"""

__version__ = "1"
