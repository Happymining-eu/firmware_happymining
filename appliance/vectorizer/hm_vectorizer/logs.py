"""Logging to standard error, with a last line of defence for secrets.

The code never passes the bearer token or the cloud API key to a log call.
The filter below is for what the code does not control: a library's
exception text, a traceback at debug level. Anything equal to a known secret
is replaced before a handler sees it.
"""

from __future__ import annotations

import logging
import os
import sys
from collections.abc import Callable, Iterable

LEVEL_ENV = "HM_VECTORIZER_LOG_LEVEL"
_LEVELS = {"DEBUG": logging.DEBUG, "INFO": logging.INFO, "WARNING": logging.WARNING, "ERROR": logging.ERROR}
REDACTED = "[redacted]"


class RedactingFilter(logging.Filter):
    def __init__(self, secrets: Callable[[], Iterable[str | None]]) -> None:
        super().__init__()
        self._secrets = secrets
        self._formatter = logging.Formatter()

    def _redact(self, text: str) -> str:
        for secret in self._secrets():
            if secret and secret in text:
                text = text.replace(secret, REDACTED)
        return text

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:
            message = str(record.msg)
        record.msg = self._redact(message)
        record.args = ()
        if record.exc_info:
            record.exc_text = self._redact(self._formatter.formatException(record.exc_info))
            record.exc_info = None
        elif record.exc_text:
            record.exc_text = self._redact(record.exc_text)
        if record.stack_info:
            record.stack_info = self._redact(record.stack_info)
        return True


def setup_logging(secrets: Callable[[], Iterable[str | None]]) -> None:
    level = _LEVELS.get(os.environ.get(LEVEL_ENV, "INFO").upper(), logging.INFO)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    handler.addFilter(RedactingFilter(secrets))
    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(level)
